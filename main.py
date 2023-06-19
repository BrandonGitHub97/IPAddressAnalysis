
# Import the IPWhois module
from ipwhois import IPWhois
import ipwhois

# IPWhois utility - Country Code Mapping
from ipwhois.utils import get_countries

# Import the JSON module - To be used for outputting dictionaries in part 4
import json

# --------------------------------------------------------------------------------------------------------------------------------------

# file_input_output Function Call
def file_input_output():
    # Initialize lists
    file_contents = []
    list_of_ip_addresses = []
    ip_address_list = []
    splitted_list = []
    unique_addresses = []

    try:
        # Open the DDoSRawLog input file with read access.
        with open("DDoSRawLog.txt", "r") as input_file:
            # Read the contents of the file into a list.
            file_contents = input_file.readlines()

    except FileNotFoundError:
        print("\nError reading file. File could not be found.\n")

    # Split each line in the file_contents list and append the splitted sections to a new list.
    for line in file_contents:
        sections = line.split()
        splitted_list.append(sections)

    # Iterate over each line in the list.
    for line in splitted_list:
        # Iterate over each item within each line.
        for item in line:
            # Extract the IP address (the 7th item in each line) and append it to a new list.
            ip_address = line[7]
            ip_address_list.append(ip_address)

    # Convert the list to a set to remove duplicate IP addresses, then back to a list.
    ip_address_set = set(ip_address_list)
    list_of_ip_addresses = list(ip_address_set)

    # Iterate through the list, removing any ']' characters, and append to a new list.
    for item in list_of_ip_addresses:
        ip_address = item.replace("]", "")
        unique_addresses.append(ip_address)

    # Sort the list of unique addresses.
    unique_addresses.sort()

    # Open the output file with write access and write the IP addresses to it.
    with open("output_file.txt", "w") as output_file:
        # Append the IP addresses vertically to the output file.
        for ip_address in unique_addresses:
            output_file.write("%s\n" % ip_address)

    print("\n- The IP addresses have been successfully outputted to the file -\n")

    # Return the list of unique IP addresses to the main function.
    return unique_addresses


# --------------------------------------------------------------------------------------------------------------------------------------


# determine_ip_class Function Definition
def determine_ip_class(list_of_ip_addresses):
    # Initialize lists to store IP addresses of each class.
    ip_address_class_a = []
    ip_address_class_b = []
    ip_address_class_c = []
    ip_address_class_d = []
    ip_address_class_e = []

    # Split each IP address into sections by the '.' character.
    for item in list_of_ip_addresses:
        octet = item.split(".")

        # Convert the network ID section (octet[0]) from a string to an integer.
        int_octet = int(octet[0])

        # Check if the network ID section of each IP address is in range. If so, append the full IP address to its corrosponding class list.
        if int_octet >= 1 and int_octet <= 127:
            # Convert int_octet from an integer back to an string amd concatenate each section together.
            str_octet = str(int_octet)
            ip_address = str_octet + "." + octet[1] + "." + octet[2] + "." + octet[3]
            ip_address_class_a.append(ip_address)

        if octet[0] >= "128" and octet[0] <= "191":
            ip_address = octet[0] + "." + octet[1] + "." + octet[2] + "." + octet[3]
            ip_address_class_b.append(ip_address)

        if octet[0] >= "192" and octet[0] <= "223":
            ip_address = octet[0] + "." + octet[1] + "." + octet[2] + "." + octet[3]
            ip_address_class_c.append(ip_address)

        if octet[0] >= "224" and octet[0] <= "239":
            ip_address = octet[0] + "." + octet[1] + "." + octet[2] + "." + octet[3]
            ip_address_class_d.append(ip_address)

        if octet[0] >= "240" and octet[0] <= "255":
            ip_address = octet[0] + "." + octet[1] + "." + octet[2] + "." + octet[3]
            ip_address_class_e.append(ip_address)

    # For display purposes
    print("-" * 155, "\n")

    # Assign all of the IP address class lists to a dictionary
    ip_address_classes = {
        "Class A": ip_address_class_a,
        "Class B": ip_address_class_b,
        "Class C": ip_address_class_c,
        "Class D": ip_address_class_d,
        "Class E": ip_address_class_e,
    }

    print(
        "- The following IP addresses have been extracted from the syslog and assigned to their respective class ranges -\n"
    )

    # Display the IP addresses associated with each class of IP address
    for key in ip_address_classes:
        print(key, "IP addresses:", *ip_address_classes[key], "\n\n")

    # Return the ip_address_classes dictionary to the main function
    return ip_address_classes


# --------------------------------------------------------------------------------------------------------------------------------------


# ipwhois_identification Function Definition (PART 3)
def ipwhois_identification(list_of_ip_addresses):
    # For display purposes
    print("-" * 150, "\n")

    # Initialise empty dictionary.
    ipwhois_information = {}

    print("- Performing IPWhois lookups -\n")

    # Iterate through the list of IP addresses.
    for ip_address in list_of_ip_addresses:
        try:
            # Identify the source of the IP address using a “whois” lookup.
            countries = get_countries()
            obj = IPWhois(ip_address, timeout=300)
            results_dictionary = obj.lookup_whois(False)

            # For display purposes
            print("#" * 80)

            # Display the country of origin and description fields returned by the whois lookup.
            print(
                "\nIPWhois lookup information for the following IP address:", ip_address
            )
            print(
                "\n\tCountry of Origin:",
                countries[results_dictionary["nets"][0]["country"]],
            )

            print("\tDescription Fields:", results_dictionary["asn_description"], "\n")

            # Assign the country and description to a list
            information = [
                countries[results_dictionary["nets"][0]["country"]],
                results_dictionary["asn_description"],
            ]

            # Update the ipwhois_information dictionary - Make each IP address a key and assign its corresponding information as the value.
            ipwhois_information.update({ip_address: information})

        except ipwhois.exceptions.HTTPLookupError as error:
            print("#" * 80)
            print(
                "\nAn error occurred. A socket operation was attempted to an unreachable network\n",
                "\tInformation:",
                error,
                "\n",
            )

            # Continue the loop if an exception occurs
            continue

        except ipwhois.exceptions.ASNRegistryError:
            print(
                "\nASN lookup failed with no more methods to try. Due to no internet connection\n"
            )

            # Continue the loop if an exception occurs
            continue

    # Return the ipwhois_information to the main function
    return ipwhois_information


# --------------------------------------------------------------------------------------------------------------------------------------


# file_output Function Definition
def file_output(ip_address_class_info, ipwhois_information):
    # Assign both dictionaries to a list
    dict_list = [ip_address_class_info, ipwhois_information]

    try:
        # Open the output file with write access and write the information gathered to it.
        with open("final_output_file.json", "w") as output_file:
            # Write out the information gathered to the output file.
            json.dump(dict_list, output_file, indent=2)

        # For display purposes
        print("#" * 80)

        print("\n- The information has been outputted to the file. -\n")

    except PermissionError as error:
        print("\nYou do not have permission to write to the file.\n", error)
    except IOError as error:
        print("\nIssue encountered with input/output operations.\n", error)


# --------------------------------------------------------------------------------------------------------------------------------------


# main Function Definition
def main():
    # file_input_output Function Call
    list_of_ip_addresses = file_input_output()

    # determine_ip_class Function Call
    ip_address_class_info = determine_ip_class(list_of_ip_addresses)

    # ipwhois_identification Function Call
    ipwhois_information = ipwhois_identification(list_of_ip_addresses)

    # file_output Function Call
    file_output(ip_address_class_info, ipwhois_information)


# Main Function Call
if __name__ == "__main__":
    main()
