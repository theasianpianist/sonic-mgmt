import argparse

import pytest
from tests.common import constants


def _non_negative_int(value):
    value = int(value)
    if value < 0:
        raise argparse.ArgumentTypeError(
            "value must be greater than or equal to zero"
        )
    return value


def _positive_int(value):
    value = int(str(value), 0)
    if value <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return value


# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests

    route_group = parser.getgroup("Route test suite options")

    route_group.addoption("--max_scale", action="store_true",
                          help="Test with maximum possible route scale")
    route_group.addoption(
        "--route_perf_monitor_pre_seconds",
        action="store",
        default=30,
        type=_non_negative_int,
        help="Seconds to monitor before programming routes",
    )
    route_group.addoption(
        "--route_perf_monitor_post_seconds",
        action="store",
        default=30,
        type=_non_negative_int,
        help="Seconds to monitor after route and DUT cleanup",
    )
    route_group.addoption(
        "--route_perf_monitor_action_pause_seconds",
        action="store",
        default=10,
        type=_non_negative_int,
        help="Seconds to monitor after each action before starting the next one",
    )
    route_group.addoption(
        "--route_perf_pause_after_routes_seconds",
        action="store",
        default=0,
        type=_non_negative_int,
        help="Seconds to pause after submitting routes and before ASIC validation",
    )
    route_group.addoption(
        "--route_perf_route_source",
        action="store",
        default="swssconfig",
        choices=["swssconfig", "bgp"],
        help="Route injection source for the monitored IPv6 /126 test",
    )
    route_group.addoption(
        "--route_perf_ipv6_route_spacing",
        action="store",
        default=1 << 64,
        type=_positive_int,
        help=(
            "Address delta between monitored IPv6 /126 route starts; "
            "defaults to 2^64 to preserve the existing /64-style pattern"
        ),
    )


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope='module', params=[4, 6])
def ip_versions(request):
    """
    Parameterized fixture for IP versions.
    """
    yield request.param


@pytest.fixture(scope="module")
def is_backend_topology(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
        Check if the current test is running on the backend topology.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)

    return is_backend_topology
