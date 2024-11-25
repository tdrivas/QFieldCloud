from django.core.exceptions import ObjectDoesNotExist
from drf_spectacular.utils import extend_schema, extend_schema_view

from rest_framework.exceptions import PermissionDenied

from qfieldcloud.core import pagination, permissions_utils, querysets_utils
from qfieldcloud.core.models import (
    Organization,
    Project,
    TeamMember,
    Team,
)
from qfieldcloud.core.serializers import (
    CompleteUserSerializer,
    OrganizationSerializer,
    PublicInfoUserSerializer,
    TeamListSerializer,
    TeamMemberSerializer,
    TeamSerializer,
    AddMemberSerializer,
    TeamAccessSerializer,
)

from qfieldcloud.core.permissions_utils import can_create_teams

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from ..querysets_utils import get_team_members


class ListUsersViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        return permissions_utils.can_list_users_organizations(request.user)


@extend_schema_view(
    get=extend_schema(description="List users and/or organizations"),
)
class ListUsersView(generics.ListAPIView):
    serializer_class = PublicInfoUserSerializer
    permission_classes = [permissions.IsAuthenticated, ListUsersViewPermissions]
    pagination_class = pagination.QfcLimitOffsetPagination()

    def get_queryset(self):
        params = self.request.GET
        query = params.get("q", "")

        project = None
        if params.get("project"):
            try:
                project = Project.objects.get(id=params.get("project"))
            except Project.DoesNotExist:
                pass

        organization = None
        if params.get("organization"):
            try:
                organization = Organization.objects.get(
                    username=params.get("organization")
                )
            except Project.DoesNotExist:
                pass

        # TODO : are these GET paremters documented somewhere ? Shouldn't we use something
        # like django_filters.rest_framework.DjangoFilterBackend so they get auto-documented
        # in DRF's views, or is that supposedly done with swagger ?
        exclude_organizations = bool(int(params.get("exclude_organizations") or 0))
        exclude_teams = bool(int(params.get("exclude_teams") or 0))
        invert = bool(int(params.get("invert") or 0))
        return querysets_utils.get_users(
            query,
            project=project,
            organization=organization,
            exclude_organizations=exclude_organizations,
            exclude_teams=exclude_teams,
            invert=invert,
        )


class RetrieveUpdateUserViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        username = permissions_utils.get_param_from_request(request, "username")

        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            return False

        if request.method == "GET":
            # The queryset is already filtered by what the user can see
            return True
        if request.method in ["PUT", "PATCH"]:
            return permissions_utils.can_update_user(request.user, user)
        return False


@extend_schema_view(
    retrieve=extend_schema(
        """Retrieve a single user's (or organization) publicly
        information or complete info if the request is done by the user
        himself"""
    ),
    put=extend_schema("Update a user"),
    patch=extend_schema("Partially update a user"),
)
class RetrieveUpdateUserView(generics.RetrieveUpdateAPIView):
    """Get or Update the authenticated user"""

    permission_classes = [
        permissions.IsAuthenticated,
        RetrieveUpdateUserViewPermissions,
    ]
    serializer_class = CompleteUserSerializer

    def get_object(self):
        username = self.request.parser_context["kwargs"]["username"]
        return User.objects.get(username=username)

    def get(self, request, username):
        user = User.objects.get(username=username)

        if user.type == User.Type.ORGANIZATION:
            organization = Organization.objects.of_user(request.user).get(
                username=username
            )
            serializer = OrganizationSerializer(organization)
        else:
            if request.user == user:
                serializer = CompleteUserSerializer(user)
            else:
                serializer = PublicInfoUserSerializer(user)

        return Response(serializer.data)


class ListUserOrganizationsViewPermissions(permissions.BasePermission):
    def has_permission(self, request, view):
        username = permissions_utils.get_param_from_request(request, "username")

        if request.user.username != username:
            return False

        if request.method == "GET":
            return True

        return False


@extend_schema_view(
    get=extend_schema(description="Get a user's organization"),
)
class ListUserOrganizationsView(generics.ListAPIView):
    """Get user's organizations"""

    permission_classes = [
        permissions.IsAuthenticated,
        ListUserOrganizationsViewPermissions,
    ]
    serializer_class = OrganizationSerializer

    def get_queryset(self):
        return Organization.objects.of_user(self.request.user)


class TeamMemberDeleteView(APIView):
    def delete(self, request, organization_name, team_name, member_username):
        """
        DELETE /organizations/<str:organization_name>/team/<str:team_name>/members/<str:member_username>/
        Remove a specific member from a team within an organization.
        """
        organization = get_object_or_404(Organization, username=organization_name)
        team_full_name = f"@{organization_name}/{team_name}"
        team = get_object_or_404(
            Team, team_organization=organization, username=team_full_name
        )
        member = get_object_or_404(User, username=member_username)
        team_member = get_object_or_404(TeamMember, team=team, member=member)

        if not permissions_utils.can_manage_team(request.user, team):
            raise PermissionDenied(
                "You do not have permission to remove members from this team."
            )

        team_member.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class TeamDetailView(APIView):
    def get(self, request, organization_name, team_name):
        """
        GET /organizations/<str:organization_name>/team/<str:team_name>/
        Retrieve the details of a specific team within the organization.
        """
        organization = get_object_or_404(Organization, username=organization_name)
        team_name = f"@{organization_name}/{team_name}"
        team = get_object_or_404(
            Team, team_organization=organization, username=team_name
        )

        serializer = TeamAccessSerializer(team, data={"request": request})

        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, organization_name, team_name):
        """
        PUT /organizations/<str:organization_name>/team/<str:team_name>/
        Update a team's name within the organization.
        """
        organization = get_object_or_404(Organization, username=organization_name)
        team_name = f"@{organization_name}/{team_name}"
        team = get_object_or_404(
            Team, team_organization=organization, username=team_name
        )

        if not can_create_teams(request.user, organization):
            return Response(
                {
                    "error": "You do not have permission to edit teams in this organization."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        new_team_name = request.data.get("username")

        if not new_team_name:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if Team.objects.filter(
            team_organization=organization, username=new_team_name
        ).exists():
            return Response(status=status.HTTP_400_BAD_REQUEST)

        new_team_name = f"@{organization_name}/{new_team_name}"
        team.username = new_team_name

        team.save()

        serializer = TeamSerializer(team)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, organization_name, team_name):
        """
        DELETE /organizations/<str:organization_name>/team/<str:team_name>/
        Delete a team within the organization.
        """
        organization = get_object_or_404(Organization, username=organization_name)
        team_name = f"@{organization_name}/{team_name}"
        team = get_object_or_404(
            Team, team_organization=organization, username=team_name
        )

        if not permissions_utils.can_manage_team(request.user, team):
            raise PermissionDenied(
                "You do not have permission to remove team from this organization."
            )

        team.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class TeamListCreateView(APIView):
    def get(self, request, organization_name):
        """
        Handle GET request: Retrieve all teams under a specific organization --> organizations/<str:organization_name>/team/
        """
        organization = get_object_or_404(Organization, username=organization_name)

        teams = querysets_utils.get_organization_teams(organization)

        serializer = TeamListSerializer(teams, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, organization_name):
        """
        Handle POST request: Create a new team under a specific organization.
        """
        organization = get_object_or_404(Organization, username=organization_name)

        if not can_create_teams(request.user, organization):
            return Response(
                {
                    "error": "You do not have permission to create teams in this organization."
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        team_name = request.data.get("username")

        if not team_name:
            return Response(
                {"error": "Team name is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        team_name = f"@{organization_name}/{team_name}"

        if Team.objects.filter(
            team_organization=organization, username=team_name
        ).exists():
            return Response(
                {"error": "Team with this name already exists."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        new_team = Team.objects.create(
            username=team_name,
            team_organization=organization,
        )

        serializer = TeamSerializer(new_team)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class TeamMemberView(APIView):
    """
    View to handle adding and listing team members. --> organizations/<str:organization_name>/team/<str:team_name>/members/"
    """

    def post(self, request, organization_name, team_name):
        organization = get_object_or_404(Organization, username=organization_name)
        team_full_name = f"@{organization_name}/{team_name}"
        team = get_object_or_404(
            Team, username=team_full_name, team_organization=organization
        )

        if not permissions_utils.can_add_members_to_team(request.user, team):
            raise PermissionDenied(
                "You do not have permission to remove members from this team."
            )

        serializer = AddMemberSerializer(
            data=request.data, context={"organization": organization}
        )

        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        team_member, created = TeamMember.objects.get_or_create(team=team, member=user)

        if created:
            return Response(
                {"message": f"{user.username} added to {team_name} team"},
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(
                {"message": f"{user.username} is already a member of {team_name}"},
                status=status.HTTP_200_OK,
            )

    def get(self, request, organization_name, team_name):
        """List all members of a team within an organization."""

        team_name = "@" + organization_name + "/" + team_name
        organization = get_object_or_404(Organization, username=organization_name)
        team = get_object_or_404(
            Team, username=team_name, team_organization=organization
        )
        members = get_team_members(team)

        serializer = TeamMemberSerializer(members, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
