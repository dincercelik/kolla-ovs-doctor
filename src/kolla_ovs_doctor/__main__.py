"""Run ovs-doctor as python -m kolla_ovs_doctor."""
import sys

from kolla_ovs_doctor.cli import main

sys.exit(main())
