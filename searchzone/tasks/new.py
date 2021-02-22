import logging
import re

import idna

from searchzone.tasks.helper import timestamp_now, check_dot_end, get_record, get_additional_records

LOGGER = logging.getLogger(__name__)


def new(appsearch, queue, init=False):
    while True:
        domain = queue.get()
        new_adding(appsearch, domain, init)
        queue.task_done()

def init_entry():
    answer = {}
    local_time = timestamp_now()
    answer['domain_valid'] = True
    answer['info_valid'] = False
    answer['registry'] = ""

    answer['timestamp_firstseen'] = str(local_time.isoformat())
    answer['timestamp_lastseen'] = '1970-01-01T02:00:00.000000+01:00'
    return answer

def new_adding(appsearch, domain, init):
    if init:
        answer = init_entry()
    else:
        answer = {}

    local_time = timestamp_now()
    answer['id'] = domain
    answer['timestamp'] = str(local_time.isoformat())
    rr_list = ['A', 'AAAA', 'NS', 'TXT', 'MX', 'DS', 'DNSKEY', 'CAA', 'SOA']
    rr_add_list = ['DMARC']

    timeout = 3.0
    if check_dot_end(domain):
        domain = domain[:-1]

    LOGGER.debug('Adding domain: %s', domain)
    try:
        answer['domain'] = idna.decode(domain)
        get_record(domain, rr_list, answer, timeout)
        get_additional_records(domain, rr_add_list, answer)
        if re.search("spf1", str(answer.get("txt_record"))):
            answer['spf_valid'] = True
        else:
            answer['spf_valid'] = False
    except idna.IDNAError:
        answer['domain'] = domain
    if init:
        appsearch.insert_new_document(answer)
    else:
        appsearch.update_existing_document(answer)
