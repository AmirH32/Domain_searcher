# Domain_searcher
Domain search tool using both ICANN czds and WHOis domain discovery API 

# INSTALLATION  
Please follow this process  
If you would like to use the ICANN scanner:   
  
1). Open the config.json file and enter your ICANN czds username and password into the respective fields (https://czds.icann.org/home), on the CZDS platform request zone files from the registrars you wish to use in your search.  
  
2). Start the Domain_Lookup.py program and select option 3 and then select if you would like to download all or some of the files you requested access for (keep in mind these files can be large - up to around 5GB)  
  
If you would like to use the WHOIS scanner:  
1). Go to https://user.whoisxmlapi.com/products after making a WHOIS API account  
2). Copy your API key  
3). Insert your API key into the API key field in the WHOIS_lookup.py script  
