import dns.resolver
import logging
import argparse
import re
import dotenv

# Load environment variables from .env file
dotenv.load_dotenv()

logging.basicConfig(level=logging.INFO)
# Set up logging to console
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

lookups = 0
lookup_domains = []

def get_spf_record(domain: str, recursion_limit: int) -> str:
    """
    Fetch the SPF record for a given domain and process includes up to the recursion limit.

    Args:
        domain (str): The domain to fetch the SPF record for.
        recursion_limit (int): The limit for processing included SPF records.

    Returns:
        str: The SPF record if found, otherwise a message indicating it wasn't found.
    """
    try:
        global lookups
        if domain in lookup_domains:
            return "Domain already looked up"
        lookup_domains.append(domain)
        lookups += 1
        logger.info(f"Querying for SPF records of domain {domain}")
        answers = dns.resolver.resolve(domain, 'TXT')
        for record in answers:
            record_str = record.to_text().strip('"')
            if record_str.startswith('v=spf1'):
                # Log the SPF record found, indented with the recursion level
                indent = '  ' * (10 - recursion_limit - 1)
                logger.debug(f"{indent}SPF record found for domain {domain}: {record_str}")

                return process_spf_record(record_str, domain, recursion_limit)
        logger.info(f"No SPF record found for domain {domain}")
        return "No SPF record found"
    except dns.resolver.NoAnswer:
        logger.error(f"No answer was received when querying for SPF records of domain {domain}")
        return "No answer received for SPF record query"
    except dns.resolver.NXDOMAIN:
        logger.error(f"The domain {domain} does not exist")
        return "Domain does not exist"
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return f"An error occurred: {e}"

def process_spf_record(record: str, domain: str, recursion_limit: int, current_level: int = 0) -> str:
    """
    Process the SPF record to count the mechanisms and handle include mechanisms.

    Args:
        record (str): The SPF record to process.
        domain (str): The domain being processed.
        recursion_limit (int): The limit for processing included SPF records.
        current_level (int): The current recursion level.

    Returns:
        str: The processed SPF record or error message.
    """
    mechanisms = record.split()
    count = 0

    for mech in mechanisms:
        if mech.startswith('include:'):
            if current_level >= recursion_limit:
                return f"Exceeded recursion limit of {recursion_limit} for includes in domain {domain}"
            include_domain = mech.split(':')[1]
            include_domain_expanded = expand_macros(include_domain, domain)
            include_record = get_spf_record(include_domain_expanded, recursion_limit - 1)
            if "No SPF record found" in include_record or "error" in include_record:
                return include_record
            processed_include = process_spf_record(include_record, include_domain_expanded, recursion_limit, current_level + 1)
            logger.debug(f"Processed include: {processed_include}")
            if "error" in processed_include:
                return processed_include
            count += len(processed_include.split())
        else:
            count += 1

    
    return record

def expand_macros(domain: str, base_domain: str) -> str:
    """
    Expand macros in the domain string based on a given base domain.

    Args:
        domain (str): The domain string containing macros.
        base_domain (str): The base domain to use for expansion.

    Returns:
        str: The domain string with macros expanded.
    """
    # Example values for macro expansion
    sender_ip = '192.0.2.1'
    sender_email = f'user@{base_domain}'
    local_part = sender_email.split('@')[0]
    domain_part = sender_email.split('@')[1]
    reverse_ip = '.'.join(reversed(sender_ip.split('.')))

    replacements = {
        '%{s}': sender_email,
        '%{l}': local_part,
        '%{d}': domain_part,
        '%{i}': sender_ip,
        '%{p}': 'unknown',
        '%{h}': 'mail.' + domain_part,
        '%{c}': sender_ip,
        '%{r}': 'unknown',
        '%{t}': '0',
        '%{ir}': reverse_ip,
        '%{v}': 'in-addr' if ':' not in sender_ip else 'ip6',
        '%{h}': 'mail.' + domain_part
    }

    def macro_replacer(match):
        macro = match.group(0)
        return replacements.get(macro, macro)

    expanded_domain = re.sub(r'%{[slidphcrtvirhv]}', macro_replacer, domain)
    logger.debug(f"Expanded domain: {expanded_domain}")

    return expanded_domain

def flatten_spf_record(record: str, recursion_limit: int, current_level: int = 0) -> str:
    """
    Flatten the SPF record by resolving includes to their actual IP addresses.

    Args:
        record (str): The SPF record to flatten.
        recursion_limit (int): The limit for processing included SPF records.
        current_level (int): The current recursion level.

    Returns:
        str: The flattened SPF record.
    """
    mechanisms = record.split()
    flattened_record = []

    for mech in mechanisms:
        if mech.startswith('include:'):
            if current_level >= recursion_limit:
                return f"Exceeded recursion limit of {recursion_limit} for includes"
            include_domain = mech.split(':')[1]
            include_domain_expanded = expand_macros(include_domain, domain)
            include_record = get_spf_record(include_domain_expanded, recursion_limit - 1)
            if "No SPF record found" in include_record or "error" in include_record:
                return include_record
            flattened_include = flatten_spf_record(include_record, recursion_limit, current_level + 1)
            if "error" in flattened_include:
                return flattened_include
            flattened_record.extend(flattened_include.split())
        else:
            flattened_record.append(mech)
    
    return ' '.join(flattened_record)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch and process the SPF record for a domain")
    parser.add_argument("domain", type=str, help="The domain to fetch the SPF record for")
    parser.add_argument("-n", "--recursion-limit", type=int, default=5, help="The limit for processing included SPF records")
    parser.add_argument("--flatten", action="store_true", help="Flatten the SPF record by resolving includes to IP addresses")
    args = parser.parse_args()

    # Debug args
    logger.debug(f"Domain: {args.domain}")
    logger.debug(f"Recursion limit: {args.recursion_limit}")
    logger.debug(f"Flatten: {args.flatten}")

    spf_record = get_spf_record(args.domain, args.recursion_limit)
    if args.flatten:
        spf_record = flatten_spf_record(spf_record, args.recursion_limit)
    
    print(f"Lookups: {lookups}")
    if lookups > 10:
        print("Warning: More than 10 lookups were performed")

# Run the script with the domain to fetch the SPF record for
# python spf-tool.py example.com
# python spf-tool.py example.com --flatten
# python spf-tool.py example.com --recursion-limit 10
# python spf-tool.py example.com --recursion-limit 10 --flatten
