## Nuclei 
```
There are many vulnerability scanners which almost all do the same job, the problem with pretty much all of them is they use their own definitions that cannot be changed easily by the user.
Nuclei is a vulnerability scanner that makes it easy to add your own definitions using yaml templates.
Nuclei has gained in popularity due to the fact you can write your own template definitions, as well as rate-limiting, Template Filters, Workflows and basic use.

Nuclei supports HTTP, DNS, TCP, Files.
Because we can add templates ourselves we can use nuclei to perform tedious tasks that are repeated on each engagement, items such as:
Checking for DNS Records
Checking for Headers / Known files

These tasks can be completely automated once a work program is made.

Install:
Nuclei is not included by default in kali linux, you can install using apt or download the latest version directly from the Project Discovery git repository:
https://github.com/projectdiscovery/nuclei

sudo apt install nuclei

The first time you run nuclei, it will download the template database. It's good practice to manually update the template db fairly often with the -ut flag.

nuclei -ut <-- Update template databse

Scan a target:
nuclei -u example.com

Scan multiple target URLs from a list:
nuclei -l targets.txt <-- Each URL in the file must be a seperate line

Be aware that without any flags nuclei can easily trigger firewalls or DDOS protection, which  in a worst case scenario could mean we are blocked by a large content provider such as ekimai and are unable to reach any content hosted by them.

Rate Limiting
Limit the speed at which requests are sent to the server, we can limit the templates that are run on the server using filtering or exclusion rules.
To limit the speed of the request we have several options:
-rl, -rate-limit <int>  <-- Sets a limit to the requests per second, this value overrides the other two values that can be set, one of these values is the bulksize flag:
-bs, -bulk-size <int>  <-- This sets the amount of parallel connections that nuclei is allowed to make, the other options is the c flag:
-c, -concurrency <int>  <-- This flag sets the maximun number of templates that are allowed to run in parallel.

Filters:
We can use filters to limit the templates that are used, nuclei supports several filters:
-tags <string>  <-- Filters based on tags use the -tags flag, this selects all templates containing the selected string. To find out what tags you can use, you can look inside the templates themselves
--severity <string> <-- We can search using severity with the --severity flag follwed by a string value, this uses the severity entered into the template, you can select from the following options: Info, Low, Medium, High, Critical 
-authors <string> <-- Filter based on authors sring. 

Templates themselves are by default downloaded to the local nuclei templates inside inside your home folder:
~/.local/nuclei-templates/

To prevent certain templates from being run on the target we can edit the config file, located at:
~/.config/nuclei/config.yaml  <-- You will see a section at the bottom of the config file named exclude templates, this section includes the templates you want to exclude from a scan.

View All Templates:
nuclei -tl  <-- This will display all the templates that are installed, these templates are sorted by category, we can add a category and if needed a specific template to exclude.
When we run nuclei without any flags all the templates except the templates in the exclude section will be run.

Specify a Template to run:
We can select the template we want to run with the t flag follwed by the template file or a directory containing templates:
nuclei -t ~/.local/nuclei-templates/vulnerabilities/wordpress -u example.com

Workflows
If we need to run templates in a certain sequence we can use a workflow file, this file contains template names and conditions that need to be present before the templates are run.
-w <workflow file>  <--Select a workflow file using a w flag followed by a workflow name, nuclei comes with several workflows by default, these can be found in the same folder in which the templates are downloaded.
~/.local/nuclei-templates/workflows/

Workflow files are a collection of templates and conditions that trigger the templates.
The documentation contains many examples that will help explain concepts which allow us to quickly make templates and workflows we can use in our engagements:
https://docs.projectdiscovery.io/templates/introduction
