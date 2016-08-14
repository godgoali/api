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
    """
    :param code: Status code
    :param message: Message usable in UI
    :return: JSON to output
    """
    return json.dumps({
        "code": error_codes[code],
        "message": message
    })


def restart_dns():
    call(["sudo", "pihole", "refresh"])


@app.errorhandler(404)
def page_not_found(e):
    # Returns the Pi-hole block page
    return open("/var/www/html/pihole/index.html").read()


@app.errorhandler(400)
def unknown_action(e):
    # Returned if an unknown url or set of parameters are used
    return error("incorrect_params", "Unknown action or incorrect params")


@app.errorhandler(500)
def handle_error(e):
    # Returned if some internal error occurred
    return error("unknown", "Unknown error")


@app.route("/codes", methods=["GET"])
def get_codes():
    """
    :return: The status codes that might be returned by this API
    """
    result = []

    for key in error_codes:
        result.append({
            "name": key,
            "value": error_codes[key]
        })

    return json.dumps(result)


# DNS


@app.route("/dns/whitelist", methods=["GET"])
def get_whitelist():
    """
    :return: The whitelist
    """
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
    """
    Add to the whitelist
    :return: The id of the added domain
    """
    pihole = Pihole()
    domain = request.form["domain"]

    refresh = pihole.add_whitelist(domain)

    if refresh:
        # The list needs to be updated
        pihole.export_hosts()
        restart_dns()

    domain_id = [item.get_id() for item in pihole.get_raw_whitelist()
                 if item.get_domain() == domain][0]

    return str(domain_id)


@app.route("/dns/whitelist/<int:domain_id>", methods=["GET"])
def get_whitelist_id(domain_id):
    """
    :param domain_id: ID of domain
    :return: Information on the whitelist entry
    """
    pihole = Pihole()

    domains = [item for item in pihole.get_raw_whitelist() if item.get_id() == domain_id]

    # Make sure that there's only one domain
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
    """
    Delete from the whitelist
    :param domain_id: ID of domain to delete
    :return: Status code (usually success)
    """
    pihole = Pihole()
    domains = [item.get_domain() for item in pihole.get_raw_whitelist()
               if item.get_id() == domain_id]

    # Make sure that there's only one domain
    if len(domains) == 0:
        return error("does_not_exist", "No domain found for that id")
    elif len(domains) > 1:
        return error("unknown", "Unknown error")

    refresh = pihole.remove_whitelist(domains[0])

    if refresh:
        # The list needs to be updated
        pihole.export_hosts()
        restart_dns()

    return str(error_codes["success"])


@app.route("/dns/blacklist", methods=["GET"])
def get_blacklist():
    """
    :return: The blacklist
    """
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
    """
    Add to the blacklist
    :return: The id of the added domain
    """
    pihole = Pihole()
    domain = request.form["domain"]

    refresh = pihole.add_blacklist(domain)

    if refresh:
        # The list needs to be updated
        pihole.export_hosts()
        restart_dns()

    domain_id = [item.get_id() for item in pihole.get_raw_blacklist()
                 if item.get_domain() == domain][0]

    return str(domain_id)


@app.route("/dns/blacklist/<int:domain_id>", methods=["GET"])
def get_blacklist_id(domain_id):
    """
    :param domain_id: ID of domain
    :return: Information on the blacklist entry
    """
    pihole = Pihole()

    domains = [item for item in pihole.get_raw_blacklist() if item.get_id() == domain_id]

    # Make sure that there's only one domain
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
    """
    Delete from the blacklist
    :param domain_id: ID of domain to delete
    :return: Status code (usually success)
    """
    pihole = Pihole()
    domains = [item.get_domain() for item in pihole.get_raw_blacklist()
               if item.get_id() == domain_id]

    # Make sure that there's only one domain
    if len(domains) == 0:
        return error("does_not_exist", "No domain found for that id")
    elif len(domains) > 1:
        return error("unknown", "Unknown error")

    refresh = pihole.remove_blacklist(domains[0])

    if refresh:
        # The list needs to be updated
        pihole.export_hosts()
        restart_dns()

    return str(error_codes["success"])
