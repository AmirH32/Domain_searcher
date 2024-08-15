import requests
import json


def generate_schemas(api_key, domain_patterns):
    schemas = []
    for patterns in domain_patterns:
        schema = {
            "apikey": api_key,
            "domains": {
                "include": patterns
            }
        }
        schemas.append(schema)
    return schemas

def doSomething(domain_patterns):
    api_url = "https://domains-subdomains-discovery.whoisxmlapi.com/api/v1"
    api_key = "Your API Key"
    
    with open('WHOIS_domains.json', 'r+') as json_file:
        data = json.load(json_file)
        domains = data["domainsList"]

        domainSet = set(domains)
        schemas = generate_schemas(api_key, domain_patterns)
        
        newDomains = []
        for schema in schemas:
            res = requests.post(api_url, json=schema)
            responseData = res.json()
            for domain in responseData["domainsList"]:
                if domain not in domainSet:
                    newDomains.append(domain)
        
        print()
        print("="*150)
        if len(newDomains) == 0:
            print("NO NEW DOMAINS FOUND IN SEARCH")
        else:
            print("NEW DOMAINS FOUND:")
            for domain in newDomains:
                data["domainsList"].append(domain)
                print(domain)
        
        with open("WHOIS_new_domains.txt", "w", encoding="utf-8") as new_domains_file:
            new_domains_file.write('\n'.join(newDomains) + '\n')
        
        
        data["domainsCount"] = len(data["domainsList"])
        
        with open('WHOIS_domains.json', 'w') as json_file:
            json.dump(data, json_file)

if __name__ == "__main__":
    pass