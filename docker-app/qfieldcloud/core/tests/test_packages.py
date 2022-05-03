import json
import logging
import os
import tempfile
import time
from typing import List, Tuple

import psycopg2
from django.http import FileResponse
from django.utils import timezone
from qfieldcloud.authentication.models import AuthToken
from qfieldcloud.core.geodb_utils import delete_db_and_role
from qfieldcloud.core.models import Geodb, Job, Project, Secret, User
from qfieldcloud.subscription.models import AccountType
from rest_framework import status
from rest_framework.test import APITransactionTestCase

from .utils import testdata_path

logging.disable(logging.CRITICAL)


class QfcTestCase(APITransactionTestCase):
    def setUp(self):
        # Create a user
        self.user1 = User.objects.create_user(username="user1", password="abc123")

        self.user2 = User.objects.create_user(username="user2", password="abc123")

        self.token1 = AuthToken.objects.get_or_create(user=self.user1)[0]

        # Create a project
        self.project1 = Project.objects.create(
            name="project1", is_public=False, owner=self.user1
        )

        try:
            delete_db_and_role("test", self.user1.username)
        except Exception:
            pass

        self.geodb = Geodb.objects.create(
            user=self.user1,
            dbname="test",
            hostname="geodb",
            port=5432,
        )

        self.conn = psycopg2.connect(
            dbname="test",
            user=os.environ.get("GEODB_USER"),
            password=os.environ.get("GEODB_PASSWORD"),
            host="geodb",
            port=5432,
        )

    def tearDown(self):
        self.conn.close()

    def upload_files(
        self,
        token: str,
        project: Project,
        files: List[Tuple[str, str]],
    ):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        for local_filename, remote_filename in files:
            if not local_filename:
                continue

            file = testdata_path(local_filename)
            response = self.client.post(
                f"/api/v1/files/{project.id}/{remote_filename}/",
                {"file": open(file, "rb")},
                format="multipart",
            )
            self.assertTrue(status.is_success(response.status_code))

    def wait_for_project_ok_status(self, project: Project, wait_s: int = 30):
        status = self.wait_for_project_status(project, wait_s)
        if self.wait_for_project_status() != Project.Status.OK:
            self.fail(f"Waited for ok status, but got {status}")

    def wait_for_project_status(self, project: Project, wait_s: int = 30) -> Job.Status:
        """Retrieve the project status (waiting until the processing completes)"""

        jobs = Job.objects.filter(project=project).exclude(
            status__in=[Job.Status.FAILED, Job.Status.FINISHED]
        )

        if jobs.count() == 0:
            return

        has_no_pending_jobs = False
        for _ in range(wait_s):
            if (
                Job.objects.filter(project=project, status=Job.Status.PENDING).count()
                == 0
            ):
                has_no_pending_jobs = True

            time.sleep(1)

        if not has_no_pending_jobs:
            self.fail(f"Still pending jobs after waiting for {wait_s} seconds")

        for _ in range(wait_s):
            project.refresh_from_db()
            if project.status not in [
                Job.Status.PENDING,
                Job.Status.QUEUED,
                Job.Status.STARTED,
            ]:
                return project.status
            time.sleep(1)

        self.fail(f"Waited for ok status for {wait_s} seconds")

    def upload_files_and_check_package(
        self,
        token: str,
        project: Project,
        files: List[Tuple[str, str]],
        expected_files: List[str],
        job_create_error: Tuple[int, str] = None,
        tempdir: str = None,
        invalid_layers: List[str] = [],
    ):
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        self.upload_files(token, project, files)

        before_started_ts = timezone.now()

        response = self.client.post(
            "/api/v1/jobs/",
            {
                "project_id": project.id,
                "type": Job.Type.PACKAGE,
            },
        )

        if job_create_error:
            self.assertEqual(response.status_code, job_create_error[0])
            self.assertEqual(response.json()["code"], job_create_error[1])
            return
        else:
            self.assertTrue(status.is_success(response.status_code))

        job_id = response.json().get("id")

        # Wait for the worker to finish
        for _ in range(20):
            time.sleep(3)
            response = self.client.get(f"/api/v1/jobs/{job_id}/")
            payload = response.json()

            if payload["status"] == Job.Status.FINISHED:
                response = self.client.get(f"/api/v1/packages/{project.id}/latest/")
                package_payload = response.json()

                self.assertLess(
                    package_payload["packaged_at"], timezone.now().isoformat()
                )
                self.assertGreater(
                    package_payload["packaged_at"],
                    before_started_ts.isoformat(),
                )

                sorted_downloaded_files = [
                    f["name"]
                    for f in sorted(package_payload["files"], key=lambda k: k["name"])
                ]
                sorted_expected_files = sorted(expected_files)

                self.assertListEqual(sorted_downloaded_files, sorted_expected_files)

                if tempdir:
                    for filename in expected_files:
                        response = self.client.get(
                            f"/api/v1/packages/{self.project1.id}/latest/files/project_qfield.qgs/"
                        )
                        local_file = os.path.join(tempdir, filename)

                        self.assertIsInstance(response, FileResponse)

                        with open(local_file, "wb") as f:
                            for chunk in response.streaming_content:
                                f.write(chunk)

                for layer_id in package_payload["layers"]:
                    layer_data = package_payload["layers"][layer_id]

                    if layer_id in invalid_layers:
                        self.assertFalse(layer_data["is_valid"], layer_id)
                    else:
                        self.assertTrue(layer_data["is_valid"], layer_id)

                return
            elif payload["status"] == Job.Status.FAILED:
                print(
                    "Job feedback:",
                    json.dumps(
                        Job.objects.get(id=job_id).feedback, sort_keys=True, indent=2
                    ),
                )
                self.fail("Worker failed with error")

        self.fail("Worker didn't finish")

    def test_list_files_for_qfield(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE point (id integer, geometry geometry(point, 2056))")
        self.conn.commit()
        cur.execute(
            "INSERT INTO point(id, geometry) VALUES(1, ST_GeomFromText('POINT(2725505 1121435)', 2056))"
        )
        self.conn.commit()

        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/project2.qgs", "project.qgs"),
                ("delta/points.geojson", "points.geojson"),
            ],
            expected_files=["data.gpkg", "project_qfield.qgs"],
        )

    def test_list_files_missing_qgis_project_file(self):
        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/points.geojson", "points.geojson"),
            ],
            job_create_error=(400, "no_qgis_project"),
            expected_files=[],
        )

    def test_project_never_packaged(self):
        self.upload_files(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/project2.qgs", "project.qgs"),
            ],
        )

        response = self.client.get(f"/api/v1/packages/{self.project1.id}/latest/")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_job")

    def test_download_file_for_qfield(self):
        tempdir = tempfile.mkdtemp()

        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/nonspatial.csv", "nonspatial.csv"),
                ("delta/testdata.gpkg", "testdata.gpkg"),
                ("delta/points.geojson", "points.geojson"),
                ("delta/polygons.geojson", "polygons.geojson"),
                ("delta/project.qgs", "project.qgs"),
            ],
            expected_files=[
                "data.gpkg",
                "project_qfield.qgs",
            ],
            tempdir=tempdir,
        )

        local_file = os.path.join(tempdir, "project_qfield.qgs")
        with open(local_file, "r") as f:
            self.assertEqual(
                f.readline().strip(),
                "<!DOCTYPE qgis PUBLIC 'http://mrcc.com/qgis.dtd' 'SYSTEM'>",
            )

    def test_list_files_for_qfield_broken_file(self):
        self.upload_files(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/broken.qgs", "broken.qgs"),
            ],
        )

        response = self.client.post(
            "/api/v1/jobs/",
            {
                "project_id": self.project1.id,
                "type": Job.Type.PACKAGE,
            },
        )

        self.assertTrue(status.is_success(response.status_code))
        job_id = response.json().get("id")

        # Wait for the worker to finish
        for _ in range(10):
            time.sleep(3)
            response = self.client.get(
                f"/api/v1/jobs/{job_id}/",
            )
            if response.json()["status"] == "failed":
                return

        self.fail("Worker didn't finish")

    def test_create_job_twice(self):
        self.upload_files(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/project2.qgs", "project.qgs"),
                ("delta/points.geojson", "points.geojson"),
            ],
        )

        response = self.client.post(
            "/api/v1/jobs/",
            {
                "project_id": self.project1.id,
                "type": Job.Type.PACKAGE,
            },
        )

        self.assertTrue(response.status_code, 201)

        response = self.client.post(
            "/api/v1/jobs/",
            {
                "project_id": self.project1.id,
                "type": Job.Type.PACKAGE,
            },
        )

        self.assertTrue(response.status_code, 200)

    def test_downloaded_file_has_canvas_name(self):
        tempdir = tempfile.mkdtemp()

        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/nonspatial.csv", "nonspatial.csv"),
                ("delta/testdata.gpkg", "testdata.gpkg"),
                ("delta/points.geojson", "points.geojson"),
                ("delta/polygons.geojson", "polygons.geojson"),
                ("delta/project.qgs", "project.qgs"),
            ],
            expected_files=[
                "data.gpkg",
                "project_qfield.qgs",
            ],
            tempdir=tempdir,
        )

        local_file = os.path.join(tempdir, "project_qfield.qgs")
        with open(local_file, "r") as f:
            for line in f:
                if 'name="theMapCanvas"' in line:
                    return

    def test_download_project_with_broken_layer_datasources(self):
        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/points.geojson", "points.geojson"),
                (
                    "delta/project_broken_datasource.qgs",
                    "project_broken_datasource.qgs",
                ),
            ],
            expected_files=[
                "data.gpkg",
                "project_broken_datasource_qfield.qgs",
            ],
            invalid_layers=["surfacestructure_35131bca_337c_483b_b09e_1cf77b1dfb16"],
        )

    def test_needs_repackaging_without_online_vector(self):
        self.project1.refresh_from_db()
        # newly uploaded project should always need to be packaged at least once
        self.assertTrue(self.project1.needs_repackaging)

        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/nonspatial.csv", "nonspatial.csv"),
                ("delta/testdata.gpkg", "testdata.gpkg"),
                ("delta/points.geojson", "points.geojson"),
                ("delta/polygons.geojson", "polygons.geojson"),
                ("delta/project.qgs", "project.qgs"),
            ],
            expected_files=[
                "data.gpkg",
                "project_qfield.qgs",
            ],
        )

        self.project1.refresh_from_db()
        # no longer needs repackaging since geopackage layers cannot change without deltas/reupload
        self.assertFalse(self.project1.needs_repackaging)

        self.upload_files(
            self.token1.key,
            self.project1,
            files=[
                ("delta/nonspatial.csv", "nonspatial.csv"),
            ],
        )

        self.project1.refresh_from_db()
        # a layer file changed, so we need to repackage
        self.assertTrue(self.project1.needs_repackaging)

    def test_needs_repackaging_with_online_vector(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE point (id integer, geometry geometry(point, 2056))")
        self.conn.commit()
        cur.execute(
            "INSERT INTO point(id, geometry) VALUES(1, ST_GeomFromText('POINT(2725505 1121435)', 2056))"
        )
        self.conn.commit()

        self.project1.refresh_from_db()
        # newly uploaded project should always need to be packaged at least once
        self.assertTrue(self.project1.needs_repackaging)

        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/project2.qgs", "project.qgs"),
                ("delta/points.geojson", "points.geojson"),
            ],
            expected_files=["data.gpkg", "project_qfield.qgs"],
        )

        self.project1.refresh_from_db()
        # projects with online vector layer should always show as it needs repackaging
        self.assertTrue(self.project1.needs_repackaging)

    def test_connects_via_pgservice(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE point (id integer, geometry geometry(point, 2056))")
        self.conn.commit()

        Secret.objects.create(
            name="PG_SERVICE_GEODB",
            type=Secret.Type.PGSERVICE,
            project=self.project1,
            created_by=self.project1.owner,
            value=(
                "[geodb]\n"
                "dbname=test\n"
                "host=geodb\n"
                "port=5432\n"
                f"user={os.environ.get('GEODB_USER')}\n"
                f"password={os.environ.get('GEODB_PASSWORD')}\n"
                "sslmode=disable\n"
            ),
        )

        self.upload_files(
            self.token1.key,
            self.project1,
            files=[
                ("delta/project_pgservice.qgs", "project.qgs"),
            ],
        )

        self.wait_for_project_ok_status(self.project1)
        self.project1.refresh_from_db()

        last_process_job = Job.objects.filter(type=Job.Type.PROCESS_PROJECTFILE).latest(
            "updated_at"
        )
        layers_by_id = last_process_job.feedback["outputs"]["project_details"][
            "project_details"
        ]["layers_by_id"]

        self.assertEqual(last_process_job.status, Job.Status.FINISHED)
        self.assertTrue(
            layers_by_id["point_6b900fa7_af52_4082_bbff_6077f4a91d02"]["is_valid"]
        )

    def test_has_online_vector_data(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE point (id integer, geometry geometry(point, 2056))")
        self.conn.commit()

        self.upload_files(
            self.token1.key,
            self.project1,
            files=[
                ("delta/project2.qgs", "project.qgs"),
            ],
        )

        self.wait_for_project_ok_status(self.project1)

        self.project1.refresh_from_db()

        self.assertTrue(self.project1.has_online_vector_data)

    def test_has_no_online_vector_data(self):
        self.upload_files(
            self.token1.key,
            self.project1,
            files=[
                ("delta/project.qgs", "project.qgs"),
            ],
        )

        self.wait_for_project_ok_status(self.project1)

        self.project1.refresh_from_db()

        self.assertFalse(self.project1.has_online_vector_data)

    def test_filename_with_whitespace(self):
        self.upload_files_and_check_package(
            token=self.token1.key,
            project=self.project1,
            files=[
                ("delta/nonspatial.csv", "nonspatial.csv"),
                ("delta/testdata.gpkg", "testdata.gpkg"),
                ("delta/points.geojson", "points.geojson"),
                ("delta/polygons.geojson", "polygons.geojson"),
                ("delta/project.qgs", "project.qgs"),
            ],
            expected_files=[
                "data.gpkg",
                "project_qfield.qgs",
            ],
        )

    def test_offline_non_geopackage(self):
        exts = ["qgs", "shp", "cpg", "dbf", "prj", "shx"]
        files = [
            (
                f"delta/project_with_offline_nongpkg.{ext}",
                f"project_with_offline_nongpkg.{ext}",
            )
            for ext in exts
        ]

        # When user has an account that supports non-geopackages layers, it works
        self.user1.useraccount.account_type = AccountType.objects.create(
            code="with_nongpkg",
            display_name="with_nongpkg",
            is_nongpkg_supported=True,
        )
        self.user1.useraccount.save()
        self.upload_files(self.token1.key, self.project1, files=files)
        status = self.wait_for_project_status(self.project1)
        self.assertEqual(status, Project.Status.OK)

        # When user has an account that does not supports non-geopackages layers, it fails
        self.user1.useraccount.account_type = AccountType.objects.create(
            code="without_nongpkg",
            display_name="without_nongpkg",
            is_nongpkg_supported=False,
        )
        self.user1.useraccount.save()
        self.upload_files(self.token1.key, self.project1, files=files)
        status = self.wait_for_project_status(self.project1)
        self.assertEqual(status, Project.Status.FAILED)
