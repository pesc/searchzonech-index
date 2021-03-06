import logging

from searchzone.tasks.helper import timestamp_now, check_dot_end

LOGGER = logging.getLogger(__name__)


def delete(appsearch, queue):
    while True:
        domain = queue.get()
        local_time = timestamp_now()
        if check_dot_end(domain):
            domain = domain[:-1]
        body = {'id': domain, 'domain_valid': False, 'timestamp': str(local_time.isoformat()), 'timestamp_lastseen': str(local_time.isoformat())}
        LOGGER.debug("Mark domain as invalid: %s", domain)
        appsearch.update_existing_document(body)
        queue.task_done()
