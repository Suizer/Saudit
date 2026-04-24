from .base import ModuleTestBase


class TestGitlab_OnPrem(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["gitlab_onprem", "httpx"]
    config_overrides = {"modules": {"gitlab_onprem": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(headers={"X-Gitlab-Meta": "asdf"})
        module_test.httpserver.expect_request(
            "/api/v4/projects", query_string="simple=true", headers={"Authorization": "Bearer asdf"}
        ).respond_with_json(
            [
                {
                    "id": 33,
                    "description": None,
                    "name": "saudit",
                    "name_with_namespace": "saudit / SAUDIT",
                    "path": "saudit",
                    "path_with_namespace": "sauditgroup/saudit",
                    "created_at": "2023-09-07T15:14:05.540Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@127.0.0.1:8888:saudit/saudit.git",
                    "http_url_to_repo": "http://127.0.0.1:8888/sauditgroup/saudit.git",
                    "web_url": "http://127.0.0.1:8888/sauditgroup/saudit",
                    "readme_url": "http://127.0.0.1:8888/sauditgroup/saudit/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 1,
                    "last_activity_at": "2024-03-11T19:13:20.691Z",
                    "namespace": {
                        "id": 9,
                        "name": "sauditgroup",
                        "path": "sauditgroup",
                        "kind": "group",
                        "full_path": "sauditgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/9/index.png",
                        "web_url": "http://127.0.0.1:8888/groups/sauditgroup",
                    },
                },
            ],
        )
        module_test.httpserver.expect_request(
            "/api/v4/groups", query_string="simple=true", headers={"Authorization": "Bearer asdf"}
        ).respond_with_json(
            [
                {
                    "id": 9,
                    "web_url": "http://127.0.0.1:8888/groups/sauditgroup",
                    "name": "sauditgroup",
                    "path": "sauditgroup",
                    "description": "OSINT automation for hackers.",
                    "visibility": "public",
                    "share_with_group_lock": False,
                    "require_two_factor_authentication": False,
                    "two_factor_grace_period": 48,
                    "project_creation_level": "developer",
                    "auto_devops_enabled": None,
                    "subgroup_creation_level": "owner",
                    "emails_disabled": False,
                    "emails_enabled": True,
                    "mentions_disabled": None,
                    "lfs_enabled": True,
                    "math_rendering_limits_enabled": True,
                    "lock_math_rendering_limits_enabled": False,
                    "default_branch_protection": 2,
                    "default_branch_protection_defaults": {
                        "allowed_to_push": [{"access_level": 30}],
                        "allow_force_push": True,
                        "allowed_to_merge": [{"access_level": 30}],
                    },
                    "avatar_url": "http://127.0.0.1:8888/uploads/-/system/group/avatar/9/index.png",
                    "request_access_enabled": False,
                    "full_name": "sauditgroup",
                    "full_path": "sauditgroup",
                    "created_at": "2018-05-15T14:31:12.027Z",
                    "parent_id": None,
                    "organization_id": 1,
                    "shared_runners_setting": "enabled",
                    "ldap_cn": None,
                    "ldap_access": None,
                    "marked_for_deletion_on": None,
                    "wiki_access_level": "enabled",
                }
            ]
        )
        module_test.httpserver.expect_request(
            "/api/v4/groups/sauditgroup/projects", query_string="simple=true", headers={"Authorization": "Bearer asdf"}
        ).respond_with_json(
            [
                {
                    "id": 33,
                    "description": None,
                    "name": "saudit2",
                    "name_with_namespace": "sauditgroup / saudit2",
                    "path": "saudit2",
                    "path_with_namespace": "sauditgroup/saudit2",
                    "created_at": "2023-09-07T15:14:05.540Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@blacklanternsecurity.com:sauditgroup/saudit2.git",
                    "http_url_to_repo": "http://127.0.0.1:8888/sauditgroup/saudit2.git",
                    "web_url": "http://127.0.0.1:8888/sauditgroup/saudit2",
                    "readme_url": "http://127.0.0.1:8888/sauditgroup/saudit2/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 1,
                    "last_activity_at": "2024-03-11T19:13:20.691Z",
                    "namespace": {
                        "id": 9,
                        "name": "sauditgroup",
                        "path": "sauditgroup",
                        "kind": "group",
                        "full_path": "sauditgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/9/index.png",
                        "web_url": "http://127.0.0.1:8888/groups/sauditgroup",
                    },
                },
            ]
        )
        module_test.httpserver.expect_request(
            "/api/v4/users/sauditgroup/projects", query_string="simple=true", headers={"Authorization": "Bearer asdf"}
        ).respond_with_json(
            [
                {
                    "id": 33,
                    "description": None,
                    "name": "saudit3",
                    "name_with_namespace": "sauditgroup / saudit3",
                    "path": "saudit3",
                    "path_with_namespace": "sauditgroup/saudit3",
                    "created_at": "2023-09-07T15:14:05.540Z",
                    "default_branch": "master",
                    "tag_list": [],
                    "topics": [],
                    "ssh_url_to_repo": "git@blacklanternsecurity.com:sauditgroup/saudit3.git",
                    "http_url_to_repo": "http://127.0.0.1:8888/sauditgroup/saudit3.git",
                    "web_url": "http://127.0.0.1:8888/sauditgroup/saudit3",
                    "readme_url": "http://127.0.0.1:8888/sauditgroup/saudit3/-/blob/master/README.md",
                    "forks_count": 0,
                    "avatar_url": None,
                    "star_count": 1,
                    "last_activity_at": "2024-03-11T19:13:20.691Z",
                    "namespace": {
                        "id": 9,
                        "name": "sauditgroup",
                        "path": "sauditgroup",
                        "kind": "group",
                        "full_path": "sauditgroup",
                        "parent_id": None,
                        "avatar_url": "/uploads/-/system/group/avatar/9/index.png",
                        "web_url": "http://127.0.0.1:8888/groups/sauditgroup",
                    },
                },
            ]
        )

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY"
                and e.data["technology"] == "GitLab"
                and e.data["url"] == "http://127.0.0.1:8888/"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "SOCIAL"
                and e.data["platform"] == "gitlab"
                and e.data["profile_name"] == "sauditgroup"
                and e.data["url"] == "http://127.0.0.1:8888/sauditgroup"
                and str(e.module) == "gitlab_onprem"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "http://127.0.0.1:8888/sauditgroup/saudit"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "http://127.0.0.1:8888/sauditgroup/saudit2"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "CODE_REPOSITORY"
                and "git" in e.tags
                and e.data["url"] == "http://127.0.0.1:8888/sauditgroup/saudit3"
            ]
        )
