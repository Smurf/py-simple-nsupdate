#Copyright 2025 Samuel Coles <me[at]smurf.codes>
#
#Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from dns import resolver, update, tsigkeyring
from dotenv import dotenv_values
import dns.name
import dns.query
import dns.resolver
import dns.update
import dns.rdatatype
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Set, Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DNSRecordType(Enum):
    # Based on the dnspython Rdatatypes
    # https://dnspython.readthedocs.io/en/latest/rdatatype-list.html
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    SVC = "SVC"
    NS = "NS"


@dataclass(eq=True, frozen=True)
class DNSRecord:
    name: str
    type: DNSRecordType
    dest: str
    ttl: int
    record_class: str = "IN"


class NSUpdater:
    def __init__(
        self,
        dns_zone: Optional[str] = None,
        dns_server: Optional[str] = None,
        ttl: Optional[int] = None,
        key_name: Optional[str] = None,
        key_secret: Optional[str] = None,
        key_algo: Optional[str] = None
    ):
        env_conf = dotenv_values(".env")

        self.dns_zone = dns_zone or env_conf.get("ZONE")
        self.zone = dns.name.from_text(self.dns_zone)
        self.dns_zone = self.zone.to_text()
        self.dns_server = dns_server or env_conf.get("SERVER")
        self.keyring = tsigkeyring.from_text(
            {
                key_name
                or str(env_conf.get("KEY_NAME")): key_secret
                or str(env_conf.get("KEY_SECRET"))
            }
        )

        self.ttl = ttl or int(env_conf.get("TTL"))

        self.key_algo = key_algo or "hmac-sha512"

    def get_records(self) -> Set[DNSRecord] | Set[None]:
        """Get existing DNS records matching our pattern"""
        existing_records = set()
        try:
            # Create a resolver
            res = dns.resolver.Resolver()
            res.nameservers = [self.dns_server]

            # Attempt zone transfer to get all records
            xfr = dns.query.xfr(
                self.dns_server,
                self.zone,
                keyring=self.keyring,
                keyalgorithm="hmac-sha512",
            )

            for msg in xfr:
                for rrset in msg.answer:
                    name = str(rrset.name)
                    record_type = dns.rdatatype.to_text(rrset.rdtype)
                    record_class = dns.rdataclass.to_text(rrset.rdclass)
                    if record_type in DNSRecordType._value2member_map_:
                        record = DNSRecord(
                            name,
                            DNSRecordType(record_type),
                            rrset[0],
                            rrset.ttl,
                            record_class,
                        )
                        logger.debug(f"Found record {record} in zone {self.dns_zone}.")
                        existing_records.add(record)
                    else:
                        logger.info(
                            f"Unsupported record of type {record_type} found. Skipping..."
                        )

            logger.info(f"Found {len(existing_records)} existing DNS records")
            return existing_records
        except Exception as e:
            logger.error(f"Failed to retrieve existing DNS records: {e}")
            return set()

    def create_record(self, record: DNSRecord):
        """Create DNS record for service"""
        try:
            # Create DNS update message
            update_msg = dns.update.Update(
                self.dns_zone, keyring=self.keyring, keyalgorithm=self.key_algo
            )

            fqdn = record.name + "." + self.zone.to_text()
            update_msg.add(fqdn, record.ttl, record.type.value, record.dest)
            response = dns.query.tcp(update_msg, self.dns_server)

            if response.rcode() == 0:
                logger.info(f"Successfully created DNS record for {fqdn}")
            else:
                logger.error(f"Failed to create DNS record for {fqdn}")

        except Exception as e:
            logger.error(f"Error creating DNS record for {fqdn}: {e}")

    def delete_record(self, record: DNSRecord):
        """Delete DNS record for service"""
        try:
            fqdn = record.name + "." + self.zone.to_text()
            update_msg = dns.update.Update(
                self.dns_zone, keyring=self.keyring, keyalgorithm=self.key_algo
            )

            # Remove all records for this name
            update_msg.delete(record.name)

            # Send update to DNS server
            response = dns.query.tcp(update_msg, self.dns_server)

            if response.rcode() == 0:
                logger.info(f"Successfully deleted DNS record for {fqdn}")
            else:
                logger.error(f"Failed to delete DNS record for {fqdn}")

        except Exception as e:
            logger.error(f"Error deleting DNS record for {fqdn}: {e}")
