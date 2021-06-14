from flask import g, request, url_for
from flask_jwt_extended import create_access_token
from flask_restful import Resource

from models.user import UserModel
from oa import github


# todo info same for facebook, google, twitter etc :::: parameters such as where user is stored might be different

class GithubLogin(Resource):
    @classmethod
    def get(cls):
        return github.authorize(url_for("github.authorize", _external=True))  # todo info same as on github


class GithubAuthorize(Resource):
    @classmethod
    def get(cls):
        response = github.authorized_response()

        if response is None or response.get("access_token") is None:
            error_response= {
                "error": request.args["error"],
                "error_description": request.args["error_description"]
            }
            return error_response

        g.access_token = response["access_token"]
        # todo info note user can change user name hence u might validate email too
        # todo info we can also pass token param to the arg, but cleaner code as done in oa @github.tokengetter
        github_user = github.get("user")
        github_username = github_user.data["login"]

        user = UserModel.find_by_username(github_username)

        if not user:
            user = UserModel(username=github_username, password=None)
            user.save_to_db()

        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_access_token(user.id)

        return {"access_token": access_token, "refresh_token": refresh_token}, 200
