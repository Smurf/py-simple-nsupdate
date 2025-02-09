# py-simple-nsupdate

This library allows for easily getting, creating, and deleting DNS records of the following types: A, AAAA, CNAME, SVC, NS.

This libary makes the `dnspython` package, while amazing for its own reasons, less painful to use.

## Install

To install `git clone` this repo and then `pip install .`.

#### Dependencies

    * dnspython
    * python-dotenv

## Usage

It is recommended to use a `.env` file when using this library.
##### Example `.env` file
```
ZONE="my-zone.example.com"
SERVER="192.168.0.1"
TTL=3600
KEY_NAME="my-tsig-key"
KEY_SECRET="EbWygMunevergonnagiveyouupnevergonnaletyoudown5ad11PK9nROPEaIg=="
```

```
#example.py
from simple_nsupdate import DNSRecord, DNSRecordType, NSUpdater

if __name__ == "__main__":
    # Records are relative
    # DNS zone is set in the .env file or NSUpdater constructor.
    record_name = "somehost"
    ns_updater = NSUpdater()
    new_record = DNSRecord(
        record_name,
        DNSRecordType.A,
        "192.168.1.100",
        3600,
    )
    ns_updater.create_record(new_record)
    ns_updater.delete_record(new_record)
```
