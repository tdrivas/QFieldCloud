
import psycopg2
import logging
import json
import uuid
import tempfile
import os
from pathlib import Path

import docker


DELTA_STATUS_PENDING = 1  # deltafile has been received, but have not started application
DELTA_STATUS_BUSY = 2  # currently being applied
DELTA_STATUS_APPLIED = 3  # applied correctly
DELTA_STATUS_CONFLICT = 4  # needs conflict resolution
DELTA_STATUS_NOT_APPLIED = 5
DELTA_STATUS_ERROR = 6  # was not possible to apply the deltafile

EXPORTATION_STATUS_PENDING = 1  # Export has been requested, but not yet started
EXPORTATION_STATUS_BUSY = 2  # Currently being exported
EXPORTATION_STATUS_EXPORTED = 3  # Export finished
EXPORTATION_STATUS_ERROR = 4  # was not possible to export the project


class QgisException(Exception):
    pass


class ApplyDeltaScriptException(Exception):
    pass


def load_env_file():
    """Read env file and return a dict with the variables"""

    environment = {}
    with open('../.env') as f:
        for line in f:
            if line.strip():
                splitted = line.rstrip().split('=', maxsplit=1)
                environment[splitted[0]] = splitted[1]

    return environment


def get_django_db_connection(is_test_db=False):
    """Connect to the Django db. If the param is_test_db is true
    it will try to connect to the temporary test db.
    Return the connection or None"""

    env = load_env_file()
    dbname = env.get('POSTGRES_DB')
    if is_test_db:
        dbname = 'test_' + dbname

    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=env.get('POSTGRES_USER'),
            password=env.get('POSTGRES_PASSWORD'),
            host=env.get('QFIELDCLOUD_HOST'),
            port=env.get('HOST_POSTGRES_PORT'),
        )
    except psycopg2.OperationalError:
        return None

    return conn


def set_exportation_status_and_log(projectid, old_status, new_status, exportlog={}):
    """Set the deltafile status and output into the database record """

    conn = get_django_db_connection(True)
    if not conn:
        conn = get_django_db_connection(False)

    cur = conn.cursor()
    cur.execute(
        "UPDATE core_exportation SET status = %s, updated_at = now(), exportlog = %s WHERE project_id = %s AND status = %s",
        (new_status, json.dumps(exportlog), projectid, old_status))
    conn.commit()

    cur.close()
    conn.close()


def export_project(projectid, project_file):
    """Start a QGIS docker container to export the project using libqfieldsync """

    tempdir = tempfile.mkdtemp()
    volumes = {
        tempdir: {'bind': '/io/', 'mode': 'rw'}
    }

    # If we are on local dev environment, use host network to connect
    # to the local geodb
    env = load_env_file()
    network_mode = 'bridge'
    if env.get('QFIELDCLOUD_HOST') == 'localhost':
        network_mode = 'host'

    client = docker.from_env()
    container = client.containers.create(
        'qfieldcloud_qgis',
        environment=load_env_file(),
        auto_remove=True,
        volumes=volumes,
        network_mode=network_mode,
    )

    container.start()
    container.attach(logs=True)
    container_command = 'xvfb-run python3 entrypoint.py export {} {}'.format(projectid, project_file)

    set_exportation_status_and_log(
        projectid, EXPORTATION_STATUS_PENDING, EXPORTATION_STATUS_BUSY)
    exit_code, output = container.exec_run(container_command)
    container.kill()

    logging.info(
        'export_project, projectid: {}, project_file: {}, exit_code: {}, output:\n\n{}'.format(
            projectid, project_file, exit_code, output.decode('utf-8')))

    if not exit_code == 0:
        set_exportation_status_and_log(
            projectid, EXPORTATION_STATUS_BUSY, EXPORTATION_STATUS_ERROR)
        raise QgisException(output)

    exportlog_file = os.path.join(tempdir, 'exportlog.json')
    try:
        with open(exportlog_file, 'r') as f:
            exportlog = json.load(f)
    except FileNotFoundError:
        exportlog = 'Export log not available'

    set_exportation_status_and_log(
        projectid,
        EXPORTATION_STATUS_BUSY,
        EXPORTATION_STATUS_EXPORTED,
        exportlog=exportlog)
    return exit_code, output.decode('utf-8'), exportlog


def set_delta_status_and_output(projectid, delta_id, status, output={}):
    """Set the deltafile status and output into the database record """

    conn = get_django_db_connection(True)
    if not conn:
        conn = get_django_db_connection(False)

    cur = conn.cursor()
    cur.execute("UPDATE core_delta SET status = %s, updated_at = now(), output = %s WHERE id = %s AND project_id = %s",
                (status, json.dumps(output), delta_id, projectid))
    conn.commit()

    cur.close()
    conn.close()


def create_deltafile_with_pending_deltas(projectid, tempdir):
    """Retrieve the pending deltas from the db and create a deltafile-like
    json to be passed to the apply_deltas script"""

    conn = get_django_db_connection(is_test_db=True)
    if not conn:
        conn = get_django_db_connection(is_test_db=False)

    cur = conn.cursor()
    cur.execute("SELECT id, deltafile_id, content FROM core_delta WHERE project_id = %s AND status = %s;",
                (projectid, DELTA_STATUS_PENDING))

    json_content = {
        "deltas": [],
        "files": [],
        "id": str(uuid.uuid4()),
        "project": projectid,
        "version": "1.0"
    }

    deltas = cur.fetchall()
    cur.close()
    conn.close()

    for delta in deltas:
        json_content["deltas"].append(delta[2])
        set_delta_status_and_output(projectid, delta[0], DELTA_STATUS_BUSY)

    deltafile = os.path.join(tempdir, 'deltafile.json')
    with open(deltafile, 'w') as f:
        json.dump(json_content, f)

    return deltafile


def apply_deltas(projectid, project_file, overwrite_conflicts):
    """Start a QGIS docker container to apply a deltafile unsing the
    apply-delta script"""

    tempdir = tempfile.mkdtemp()
    create_deltafile_with_pending_deltas(projectid, tempdir)

    volumes = {
        tempdir: {'bind': '/io/', 'mode': 'rw'}
    }
    client = docker.from_env()
    container = client.containers.create(
        'qfieldcloud_qgis',
        environment=load_env_file(),
        auto_remove=True,
        volumes=volumes)

    overwrite_conflicts_cmd = ''
    if overwrite_conflicts:
        overwrite_conflicts_cmd = '--overwrite-conflicts'

    container.start()
    container.attach(logs=True)
    container_command = 'xvfb-run python3 entrypoint.py apply-delta {} {} {}'.format(
        projectid, project_file, overwrite_conflicts_cmd)

    exit_code, output = container.exec_run(container_command)
    container.kill()

    logging.info(
        'apply_delta, projectid: {}, project_file: {}, exit_code: {}, output:\n\n{}'.format(
            projectid, project_file, exit_code, output.decode('utf-8')))

    deltalog_file = os.path.join(tempdir, 'deltalog.json')
    with open(deltalog_file, 'r') as f:
        deltalog = json.load(f)

        for log in deltalog:
            delta_id = log['delta_id']
            status = log['status']
            if status == 'status_applied':
                status = DELTA_STATUS_APPLIED
            elif status == 'status_conflict':
                status = DELTA_STATUS_CONFLICT
            elif status == 'status_apply_failed':
                status = DELTA_STATUS_NOT_APPLIED
            else:
                status = DELTA_STATUS_ERROR
            msg = log

            set_delta_status_and_output(projectid, delta_id, status, msg)

    # if exit_code not in [0, 1]:
    #     raise ApplyDeltaScriptException(output)
    return exit_code, output.decode('utf-8')


def check_status():
    """Launch a container to check that everything is working
    correctly."""

    client = docker.from_env()
    container = client.containers.create(
        'qfieldcloud_qgis',
        environment=load_env_file(),
        auto_remove=True)

    container.start()
    container.attach(logs=True)

    # TODO: create a command to actually start qgis and check some features
    container_command = 'echo QGIS container is running'

    exit_code, output = container.exec_run(container_command)
    container.kill()

    logging.info(
        'check_status, exit_code: {}, output:\n\n{}'.format(
            exit_code, output.decode('utf-8')))

    if not exit_code == 0:
        raise QgisException(output)
    return exit_code, output.decode('utf-8')
