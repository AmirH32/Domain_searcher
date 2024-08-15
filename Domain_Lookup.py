import gzip 
import datetime
import time
import re
from pathlib import Path
from download import get_config, get_zone_links, download_zone_files
from do_authentication import authenticate
from tqdm import tqdm
import WHOIS_lookup

def downloader():
    """
    Purpose: Downloads the most recent zone files into current working directory - can be changed via config.json
    """

    ## gets details from JSON config file
    username, password, authen_base_url, czds_base_url, working_directory = get_config()

    ## Authenticates the user
    print("Authenticate user {0}".format(username))
    access_token = authenticate(username, password, authen_base_url)

    # Gets the zone links
    print("\n"*3)
    print("="*120+"\nPLEASE READ THE FOLLOWING")
    choice = input("Would you like to retrieve all domain files on your ICANN account or only some (you specify):\n1). All\n2).Some\n:")
    if choice == '1':
        zone_links = get_zone_links(czds_base_url, access_token)
    elif choice == '2':
        tlds = input("Enter the tld zone files you would like to retrieve in the format, domain followed by space e.g. (com app etc):")
        tlds = tlds.split()
        zone_links = get_zone_links(czds_base_url, access_token, tlds)

    if not zone_links:
        exit(1)

    # Finally, download all zone files
    start_time = datetime.datetime.now()
    download_zone_files(zone_links, working_directory, access_token)
    end_time = datetime.datetime.now()
    print("{0}: DONE DONE. Completed downloading all zone files. Time spent: {1}".format(str(end_time), (end_time-start_time)))


def file_path_checker(file_path):
    """
    arg: Full file name + extension

    Purpose: checks if a file path exists

    Outputs: True or False depending on if the path is valid
    """
    if Path(file_path).is_file():
        return True
    else:
        print(f"The '{file_path}' does not exist")
        return False

def file_list_getter():
    """
    Purpose: Gets a list of filenames from the user

    Output: Returns a list of filenames
    """
    file_list = []

    ## Adds file names to a list of filenames
    files = input("Please enter the full filename (excluding .txt.gz) of the file/s in the format of filename followed by space then filename e.g. (app com red):")
    files = files.split()
    for file in files:
        if file_path_checker(Path(f"{file}.txt.gz")):
            file_list.append(file)

    # ## Checks if the user would like to add more files
    # while True:
    #     choice = input("Would you like to enter another file name (Y/N):").upper()
    #     if choice == 'Y':
    #         file = input("Please enter the full filename (excluding .gz) of the file:")
    #         ## Checks if the file path exists
    #         if file_path_checker(Path(f"{file}.gz")):
    #             file_list.append(file)
    #         else:
    #             continue
    #     elif choice == 'N':
    #         break
    #     else:
    #         print("Invalid choice")
    return file_list

def domain_list_getter():
    """
    Purpose: Gets a list of domains from the user

    Output: A list of domains to search for
    """
    search_strings = []
    search_string = input("Please enter a domain/s to search for in the format domain followed by a space e.g. (red google yahoo):")
    search_strings = search_string.split()
    print(search_strings)
    # ## Checks if the user would like to add anymore strings to the list
    # while True:
    #     choice = input("Would you like to enter another search domain/domain pattern (Y/N):").upper()
    #     if choice == 'Y':
    #         search_string = input("Please enter a domain/domain pattern to search:")
    #         search_strings.append(search_string)
    #     elif choice == 'N':
    #         break
    #     else:
    #         print("Invalid choice")
    
    return search_strings

def domain_pattern_getter():
    domain_pattern = input("Please enter the domain pattern to search for (usually word followed by space followed by other word):")
    domain_pattern = domain_pattern.split()
    print(domain_pattern)
    for index in range(0, len(domain_pattern)):
        domain_pattern[index] = f"*{domain_pattern[index]}*"
    return domain_pattern



def clear_new_domains_file():
    """
    Purpose: clears the new domains file
    """
    # Clear new_domains.txt at the start of the run
    with open("ICANN_new_domains.txt", "w", encoding="utf-8") as new_domains_file:
        # This will create or clear the file
        pass

def get_existing_domains():
    """
    Purpose: Gets the existing domains from a file containing all existing domains

    Output: Set of existing domains
    """
    # loads existing domains from ICANN_domains
    try:
        with open("ICANN_domains.txt", "r", encoding="utf-8") as existing_file:
            existing_domains = set(line.strip() for line in existing_file)
    except FileNotFoundError:
        # If the file doesn't exist, start with an empty set
        existing_domains = set()
    return existing_domains


def parse_gzip_file(file, regex_patterns, existing_domains, new_domains):
    """
    Purpose: Parses the gzip file for domains

    Output: Set of all new_domains
    """
    with gzip.open(f"{file}.txt.gz", 'rt', encoding='utf-8', errors='ignore') as gz_file:
            # write matches to new_domains_file in batches to prevent excessive IO operations
            matches = []
            for line in tqdm(gz_file, desc=f"Processing {file}", leave=False):
                parts = line.split('.')
                if len(parts) > 2:
                    fqdn = '.'.join(parts[:2])
                else:
                    fqdn = line.strip()

                if any(pattern.search(fqdn) for pattern in regex_patterns):
                    if fqdn not in existing_domains:
                        existing_domains.add(fqdn)
                        matches.append(fqdn)

                # Write matches in batches to minimize I/O operations to the new_domains file giving all domain details
                if len(matches) >= 1000:
                    with open("ICANN_new_domains.txt", "a", encoding="utf-8") as new_domains_file:
                        new_domains_file.write('\n'.join(matches) + '\n')
                    new_domains.update(matches)
                    matches = []

            # Write any remaining matches that were not yet written that didn't complete a batch to the new_domains file
            if matches:
                with open("ICANN_new_domains.txt", "a", encoding="utf-8") as new_domains_file:
                    new_domains_file.write('\n'.join(matches) + '\n')
            new_domains.update(matches)
    return new_domains

def domain_searcher():
    """
    Purpose: Loads in file of existing domains, 
    """
    search_strings = domain_list_getter()
    file_list = file_list_getter()

    # Turns search strings into regex patterns
    regex_patterns = [re.compile(re.escape(search_string)) for search_string in search_strings]

    print("Processing files...")
    start_time = time.time()  # Start timer

    existing_domains = get_existing_domains()

    clear_new_domains_file()

    # Collect new domains to write in one go to the matched_file
    new_domains = set()

    # Open the file to append new matched lines
    for file in file_list:
        new_domains.update(parse_gzip_file(file, regex_patterns, existing_domains, new_domains))

    # Updates the ICANN_domains.txt with all existing and new domains
    with open("ICANN_domains.txt", "a", encoding="utf-8") as matched_file:
        matched_file.writelines(f"{fqdn}\n" for fqdn in new_domains)
    
    end_time = time.time()  # End timer
    elapsed_time = end_time - start_time
    print(f"Time taken: {elapsed_time:.2f} seconds\n")
    print("="*150)
    if len(new_domains) > 0:
        print("New domains:")

        for fqdn in new_domains:
            print(fqdn)
    else:
        print("No new domains found")
            

def menu():
    """
    Purpose: Displays and offers the user a choice in the main menu
    """
    while True:
        print("="*150)
        choice = input("\nPLEASE READ THE FOLLOWING:\nIf gz file has been downloaded from ICANN please move it into the same directory as this script!\n1). ICANN Domain Searcher\n2). WHOIS Domain Search (Doesn't require file download)\n3). Download/update to new files\n4). Quit\n:")
        if choice == '1':
            domain_searcher()  
        elif choice == '2':
            domain_patterns = []
            domain_pattern = domain_pattern_getter()
            domain_patterns.append(domain_pattern)
            print("READ THE FOLLOWING: since each query ANDs each word, multiple queries must be made to get matches for the OR of each pattern")
            while True:
                get_another = input("Would you like to enter another search domain/domain pattern (Y/N):").upper()
                if get_another == 'Y':
                    domain_pattern = domain_pattern_getter()
                    domain_patterns.append(domain_pattern)
                elif get_another == 'N':
                    break
                else:
                    print("Invalid choice")
            WHOIS_lookup.doSomething(domain_patterns)
        elif choice == '3':
            downloader()
        elif choice == '4':
            quit()
        else:
            print("Invalid Choice")


if __name__=="__main__":
    menu()

