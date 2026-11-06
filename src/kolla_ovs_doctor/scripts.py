"""Render the shell scripts that run on the hosts, from Jinja templates in templates/.

A script for a container runs as `docker exec -i <container> bash -s [-- args]`.
The script is in a quoted heredoc, so it needs no extra quoting. Every value put
into a script goes through the quote filter.
"""
import shlex

import jinja2

# The templates are shell scripts, not HTML, so HTML escaping would break them. The
# quote filter makes values safe for the shell instead.
ENVIRONMENT = jinja2.Environment(  # nosec B701
    autoescape=False, keep_trailing_newline=True,
    loader=jinja2.PackageLoader("kolla_ovs_doctor", "templates"), lstrip_blocks=True,
    trim_blocks=True, undefined=jinja2.StrictUndefined)
SECTION_MARKER = "=====AUDIT:{}====="
ENVIRONMENT.filters["quote"] = shlex.quote
ENVIRONMENT.globals["section"] = SECTION_MARKER.format


def render(template, **values):
    """Return the script templates/<template>.sh.j2, filled in with values."""
    return ENVIRONMENT.get_template(f"{template}.sh.j2").render(**values)
