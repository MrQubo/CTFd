from flask import (
    current_app as app,
    render_template,
    request,
    redirect,
    url_for,
    session,
    Blueprint,
)
from itsdangerous.exc import BadTimeSignature, SignatureExpired, BadSignature

from CTFd.models import db, Users

from CTFd.utils import get_config
from CTFd.utils.decorators import ratelimit
from CTFd.utils import user as current_user
from CTFd.utils import config, validators
from CTFd.utils import email
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.crypto import verify_password
from CTFd.utils.logging import log
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.config import is_teams_mode
from CTFd.utils.security.signing import unserialize
from CTFd.utils.helpers import get_errors

import base64

auth = Blueprint("auth", __name__)


@auth.route("/confirm", methods=["POST", "GET"])
@auth.route("/confirm/<data>", methods=["GET"])
@ratelimit(method="POST", limit=10, interval=60)
def confirm(data=None):
    if not get_config("verify_emails"):
        # If the CTF doesn't care about confirming email addresses then redierct to challenges
        return redirect(url_for("challenges.listing"))

    # User is confirming email account
    if data and request.method == "GET":
        try:
            user_email = unserialize(data, max_age=1800)
        except (BadTimeSignature, SignatureExpired):
            return render_template(
                "confirm.html", errors=["Your confirmation link has expired"]
            )
        except (BadSignature, TypeError, base64.binascii.Error):
            return render_template(
                "confirm.html", errors=["Your confirmation token is invalid"]
            )

        user = Users.query.filter_by(email=user_email).first_or_404()
        user.verified = True
        log(
            "registrations",
            format="[{date}] {ip} - successful confirmation for {name}",
            name=user.name,
        )
        db.session.commit()
        db.session.close()
        if current_user.authed():
            return redirect(url_for("challenges.listing"))
        return redirect(url_for("auth.login"))

    # User is trying to start or restart the confirmation flow
    if not current_user.authed():
        return redirect(url_for("auth.login"))

    user = Users.query.filter_by(id=session["id"]).first_or_404()
    if user.verified:
        return redirect(url_for("views.settings"))

    if data is None:
        if request.method == "POST":
            # User wants to resend their confirmation email
            email.verify_email_address(user.email)
            log(
                "registrations",
                format="[{date}] {ip} - {name} initiated a confirmation email resend",
            )
            return render_template(
                "confirm.html",
                user=user,
                infos=["Your confirmation email has been resent!"],
            )
        elif request.method == "GET":
            # User has been directed to the confirm page
            return render_template("confirm.html", user=user)


@auth.route("/reset_password", methods=["POST", "GET"])
@auth.route("/reset_password/<data>", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=60)
def reset_password(data=None):
    if data is not None:
        try:
            name = unserialize(data, max_age=1800)
        except (BadTimeSignature, SignatureExpired):
            return render_template(
                "reset_password.html", errors=["Your link has expired"]
            )
        except (BadSignature, TypeError, base64.binascii.Error):
            return render_template(
                "reset_password.html", errors=["Your reset token is invalid"]
            )

        if request.method == "GET":
            return render_template("reset_password.html", mode="set")
        if request.method == "POST":
            user = Users.query.filter_by(name=name).first_or_404()
            user.password = request.form["password"].strip()
            db.session.commit()
            log(
                "logins",
                format="[{date}] {ip} -  successful password reset for {name}",
                name=name,
            )
            db.session.close()
            return redirect(url_for("auth.login"))

    if request.method == "POST":
        email_address = request.form["email"].strip()
        team = Users.query.filter_by(email=email_address).first()

        get_errors()

        if config.can_send_mail() is False:
            return render_template(
                "reset_password.html",
                errors=["Email could not be sent due to server misconfiguration"],
            )

        if not team:
            return render_template(
                "reset_password.html",
                errors=[
                    "If that account exists you will receive an email, please check your inbox"
                ],
            )

        email.forgot_password(email_address, team.name)

        return render_template(
            "reset_password.html",
            errors=[
                "If that account exists you will receive an email, please check your inbox"
            ],
        )
    return render_template("reset_password.html")


@auth.route("/register", methods=["POST", "GET"])
@check_registration_visibility
@ratelimit(method="POST", limit=10, interval=5)
def register():
    errors = get_errors()
    if request.method == "POST":
        name = request.form["name"]
        email_address = request.form["email"]
        password = request.form["password"]

        name_len = len(name) == 0
        names = Users.query.add_columns("name", "id").filter_by(name=name).first()
        emails = (
            Users.query.add_columns("email", "id")
            .filter_by(email=email_address)
            .first()
        )
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = validators.validate_email(request.form["email"])
        team_name_email_check = validators.validate_email(name)

        if not valid_email:
            errors.append("Please enter a valid email address")
        if email.check_email_is_whitelisted(email_address) is False:
            errors.append(
                "Only email addresses under {domains} may register".format(
                    domains=get_config("domain_whitelist")
                )
            )
        if names:
            errors.append("That user name is already taken")
        if team_name_email_check is True:
            errors.append("Your user name cannot be an email address")
        if emails:
            errors.append("That email has already been used")
        if pass_short:
            errors.append("Pick a longer password")
        if pass_long:
            errors.append("Pick a shorter password")
        if name_len:
            errors.append("Pick a longer user name")

        if len(errors) > 0:
            return render_template(
                "register.html",
                errors=errors,
                name=request.form["name"],
                email=request.form["email"],
                password=request.form["password"],
            )
        else:
            with app.app_context():
                user = Users(
                    name=name.strip(),
                    email=email_address.lower(),
                    password=password.strip(),
                )
                db.session.add(user)
                db.session.commit()
                db.session.flush()

                login_user(user)

                if config.can_send_mail() and get_config(
                    "verify_emails"
                ):  # Confirming users is enabled and we can send email.
                    log(
                        "registrations",
                        format="[{date}] {ip} - {name} registered (UNCONFIRMED) with {email}",
                    )
                    email.verify_email_address(user.email)
                    db.session.close()
                    return redirect(url_for("auth.confirm"))
                else:  # Don't care about confirming users
                    if (
                        config.can_send_mail()
                    ):  # We want to notify the user that they have registered.
                        email.sendmail(
                            request.form["email"],
                            "You've successfully registered for {}".format(
                                get_config("ctf_name")
                            ),
                        )

        log("registrations", "[{date}] {ip} - {name} registered with {email}")
        db.session.close()

        if is_teams_mode():
            return redirect(url_for("teams.private"))

        return redirect(url_for("challenges.listing"))
    else:
        return render_template("register.html", errors=errors)


@auth.route("/login", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=5)
def login():
    errors = get_errors()
    if request.method == "POST":
        name = request.form["name"]

        # Check if the user submitted an email address or a team name
        if validators.validate_email(name) is True:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(name=name).first()

        if user:
            if user and verify_password(request.form["password"], user.password):
                session.regenerate()

                login_user(user)
                log("logins", "[{date}] {ip} - {name} logged in")

                db.session.close()
                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return redirect(request.args.get("next"))
                return redirect(url_for("challenges.listing"))

            else:
                # This user exists but the password is wrong
                log("logins", "[{date}] {ip} - submitted invalid password for {name}")
                errors.append("Your username or password is incorrect")
                db.session.close()
                return render_template("login.html", errors=errors)
        else:
            # This user just doesn't exist
            log("logins", "[{date}] {ip} - submitted invalid account information")
            errors.append("Your username or password is incorrect")
            db.session.close()
            return render_template("login.html", errors=errors)
    else:
        db.session.close()
        return render_template("login.html", errors=errors)


@auth.route("/logout")
def logout():
    if current_user.authed():
        logout_user()
    return redirect(url_for("views.static_html"))
