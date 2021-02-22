import logging
import re
import sys
from datetime import datetime, timezone

import dns.resolver
import idna

LOGGER = logging.getLogger(__name__)


def check_dot_end(domain):
    return domain[len(domain) - 1] == '.'


def open_file_by_line(filename):
    try:
        with open(filename) as file:
            return file.read().splitlines()
    except OSError as err:
        LOGGER.critical("OS error: %s", format(err))
    except:
        LOGGER.critical("Unexpected error:", sys.exc_info()[0])
        raise


def add_to_queue(queue, domains):
    for domain in domains:
        queue.put(domain)
    LOGGER.info('Added ' + str(queue.qsize()) + ' domains to queue')


def read_file_and_add_to_queue(queue, file):
    add_to_queue(queue, open_file_by_line(file))


def timestamp_now():
    return datetime.now(timezone.utc).astimezone()


def get_decoded_domain(domain):
    try:
        return idna.decode(domain)
    except idna.IDNAError as err:
        LOGGER.critical("IDNA Decoding failed: %s", format(err))
        raise


def get_record(domain, rr_list, answer, timeout=1):
    for RR in rr_list:
        answer[RR.lower() + '_valid'] = False
        try:
            rr_set = dns.resolver.resolve(domain, RR, lifetime=timeout)
            for i in rr_set.response.answer:

                for j in i.items:
                    if dns.rdatatype.to_text(j.rdtype) == 'CNAME':
                        continue
                    if RR == 'MX':
                        answer.setdefault(RR.lower() + '_record', []).append(str(j.exchange))
                        LOGGER.debug("Domain: %s with RR %s result %s", domain, RR, str(j.exchange))
                        answer[RR.lower() + '_valid'] = True
                    else:
                        answer.setdefault(RR.lower() + '_record', []).append(j.to_text())
                        LOGGER.debug("Domain: %s with RR %s result %s", domain, RR, j.to_text())
                        answer[RR.lower() + '_valid'] = True
        except dns.resolver.NoAnswer:
            LOGGER.debug("No answer for " + RR + " " + domain)
        except dns.resolver.NXDOMAIN:
            LOGGER.debug("NXDOMAIN for " + RR + " " + domain)
        except dns.resolver.NoNameservers:
            LOGGER.debug("No NS for " + RR + " " + domain)
        except dns.resolver.Timeout:
            LOGGER.debug("Timeout for " + RR + " " + domain)
            timeout /= 2
            LOGGER.info("Reducing timeout for " + domain + " to: " + str(timeout))
        except:
            LOGGER.critical("Other error for " + RR + " " + domain)


#ToDo Make code more generic and don't duplicate
def get_additional_records(domain, rr_list, answer, timeout=1):
    for RR in rr_list:
        answer[RR.lower() + '_valid'] = False
        try:
            if RR=='DMARC':
                domain_dmarc = '_dmarc.' + domain
                RR_typ = "TXT"
                rr_set = dns.resolver.resolve(domain_dmarc, RR_typ, lifetime=timeout)
            for i in rr_set.response.answer:
                for j in i.items:
                    if re.search("DMARC1", str(j.to_text())):
                        answer.setdefault(RR.lower() + '_record', []).append(j.to_text())
                        LOGGER.debug("Domain: %s with RR %s result %s", domain, RR, j.to_text())
                        answer[RR.lower() + '_valid'] = True
        except dns.resolver.NoAnswer:
            LOGGER.debug("No answer for " + RR + " " + domain)
        except dns.resolver.NXDOMAIN:
            LOGGER.debug("NXDOMAIN for " + RR + " " + domain)
        except dns.resolver.NoNameservers:
            LOGGER.debug("No NS for " + RR + " " + domain)
        except dns.resolver.Timeout:
            LOGGER.debug("Timeout for " + RR + " " + domain)
            timeout /= 2
            LOGGER.info("Reducing timeout for " + domain + " to: " + str(timeout))
        except:
            LOGGER.critical("Other error for " + RR + " " + domain)