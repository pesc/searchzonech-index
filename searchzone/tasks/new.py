import logging
import re

import idna

from searchzone.tasks.helper import timestamp_now, check_dot_end, get_record, get_additional_records

LOGGER = logging.getLogger(__name__)


def new(appsearch, queue):
    while True:
        domain = queue.get()
        new_adding(appsearch, domain)
        queue.task_done()


def new_adding(appsearch, domain):
    answer = {}
    rr_list = ['A', 'AAAA', 'NS', 'TXT', 'MX', 'DS', 'DNSKEY', 'CAA', 'SOA']
    rr_add_list = ['DMARC']
    local_time = timestamp_now()
    timeout = 3.0
    if check_dot_end(domain):
        domain = domain[:-1]
    answer['id'] = domain
    answer['domain_valid'] = True
    answer['info_valid'] = False
    answer['registry'] = ""
    answer['spf_valid'] = False
    answer['timestamp'] = str(local_time.isoformat())
    answer['timestamp_firstseen'] = str(local_time.isoformat())
    answer['timestamp_lastseen'] = '1970-01-01T00:00:00.000000+01:00'
    LOGGER.debug('Adding domain: %s', domain)
    try:
        answer['domain'] = idna.decode(domain)
        get_record(domain, rr_list, answer, timeout)
        get_additional_records(domain, rr_add_list, answer)
        if re.search("spf1", str(answer.get("txt_record"))):
            answer['spf_valid'] = True
    except idna.IDNAError:
        answer['domain'] = domain
    appsearch.insert_new_document(answer)
