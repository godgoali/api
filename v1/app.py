# Copyright (c) 2016 Jacob Salmela
# Pi-hole: a DNS based ad-blocker [https://www.pi-hole.net]
#
# Pi-hole Web API
#
# The Pi-Hole is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


# IMPORTS


from pihole import Pihole, error_codes
from flask import Flask, request
from subprocess import call
import json


# SCRIPT


app = Flask(__name__)


def error(code, message):
    return json.dumps({
        "code": error_codes[code],
        "message": message
    })


def restart_dns():
    # We can set www-data to only have sudo access to the pihole command, just like before
    # If we tried calling restart_gravity here, it wouldn't be as clean
    call(["sudo", "pihole", "refresh"])


@app.errorhandler(404)
def page_not_found(e):
    return open("/var/www/html/pihole/index.html").read()


@app.errorhandler(400)
def unknown_action(e):
    return error("incorrect_params", "Unknown action or incorrect params")


@app.errorhandler(500)
def handle_error(e):
    return error("unknown", "Unknown error")


# DNS


@app.route("/dns/whitelist", methods=["GET"])
def get_whitelist():
    pihole = Pihole()
    whitelist = pihole.get_raw_whitelist()

    result = []
    for item in whitelist:
        result.append({
            "domain": item.get_domain(),
            "id": item.get_id()
        })

    return json.dumps(result)


@app.route("/dns/whitelist", methods=["POST"])
def post_whitelist():
    pihole = Pihole()
    domain = request.form["domain"]

    refresh = pihole.add_whitelist(domain)

    if refresh:
        pihole.export_hosts()
        restart_dns()

    domain_id = [item.get_id() for item in pihole.get_raw_whitelist()
                 if item.get_domain() == domain][0]

    return str(domain_id)


@app.route("/dns/whitelist/<int:domain_id>", methods=["GET"])
def get_whitelist_id(domain_id):
    pihole = Pihole()

    domains = [item for item in pihole.get_raw_whitelist() if item.get_id() == domain_id]

    if len(domains) == 0:
        return error("does_not_exist", "No domain found for that id")
    elif len(domains) > 1:
        return error("unknown", "Unknown error")

    domain = domains[0]

    return json.dumps({
        "id": domain.get_id(),
        "domain": domain.get_domain()
    })


@app.route("/dns/whitelist/<int:domain_id>", methods=["DELETE"])
def delete_whitelist_id(domain_id):
    pihole = Pihole()
    domains = [item.get_domain() for item in pihole.get_raw_whitelist()
               if item.get_id() == domain_id]

    if len(domains) == 0:
        return error("does_not_exist", "No domain found for that id")
    elif len(domains) > 1:
        return error("unknown", "Unknown error")

    refresh = pihole.remove_whitelist(domains[0])

    if refresh:
        pihole.export_hosts()
        restart_dns()

    return str(error_codes["success"])


@app.route("/dns/blacklist", methods=["GET"])
def get_blacklist():
    pihole = Pihole()
    blacklist = pihole.get_raw_blacklist()

    result = []
    for item in blacklist:
        result.append({
            "domain": item.get_domain(),
            "id": item.get_id()
        })

    return json.dumps(result)


@app.route("/dns/blacklist", methods=["POST"])
def post_blacklist():
    pihole = Pihole()
    domain = request.form["domain"]

    refresh = pihole.add_blacklist(domain)

    if refresh:
        pihole.export_hosts()
        restart_dns()

    domain_id = [item.get_id() for item in pihole.get_raw_blacklist()
                 if item.get_domain() == domain][0]

    return str(domain_id)


@app.route("/dns/blacklist/<int:domain_id>", methods=["GET"])
def get_blacklist_id(domain_id):
    pihole = Pihole()

    domains = [item for item in pihole.get_raw_blacklist() if item.get_id() == domain_id]

    if len(domains) == 0:
        return error("does_not_exist", "No domain found for that id")
    elif len(domains) > 1:
        return error("unknown", "Unknown error")

    domain = domains[0]

    return json.dumps({
        "id": domain.get_id(),
        "domain": domain.get_domain()
    })


@app.route("/dns/blacklist/<int:domain_id>", methods=["DELETE"])
def delete_blacklist_id(domain_id):
    pihole = Pihole()
    domains = [item.get_domain() for item in pihole.get_raw_blacklist()
               if item.get_id() == domain_id]

    if len(domains) == 0:
        return error("does_not_exist", "No domain found for that id")
    elif len(domains) > 1:
        return error("unknown", "Unknown error")

    refresh = pihole.remove_blacklist(domains[0])

    if refresh:
        pihole.export_hosts()
        restart_dns()

    return str(error_codes["success"])


@app.route("/dns/history", methods=["GET"])
def get_history():
    """
    :return: Raw query log
    """
    pihole = Pihole()
    history = pihole.get_log()

    result = []
    for query in history:
        result.append({
            "time": int(query.get_time().timestamp()),
            "domain": query.get_domain(),
            "client": query.get_client(),
            "queryType": query.get_record_type(),
            "blocked": query.was_blocked()
        })

    return json.dumps(result)


@app.route("/dns/history/<int:from_time>/<int:until_time>")
def get_filtered_history(from_time, until_time):
    """
    :param from_time: UNIX timestamp (inclusive)
    :param until_time: UNIX timestamp (inclusive)
    :return: Raw queries within timestamps
    """
    pihole = Pihole()
    history = pihole.get_log()

    result = []
    for query in history:
        # Convert query time to UNIX timestamp
        time = int(query.get_time().timestamp())

        if from_time <= time <= until_time:
            result.append({
                "time": time,
                "domain": query.get_domain(),
                "client": query.get_client(),
                "queryType": query.get_record_type(),
                "blocked": query.was_blocked()
            })

    return json.dumps(result)
