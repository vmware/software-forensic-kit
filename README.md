

# software-forensic-kit

## Overview
Software-Forensic-Kit is a software tool kit to help identify quickly what's inside your binary files. Often times,
your binaries, including your open source libraries, will encapsulate other open source software. This makes it 
difficult to determine if a particular function in a certain library is being used by an application on your system. 
This tool kit will help you find plausible paths to functions of interest by searching through your already built 
binaries and generating filtered callgraphs.  
 
![Software-Forensic-Kit Deployment](doc/images/deployment1.png)


### Prerequisites

* Requires Java 1.8+
* Requires Maven 3.x+

### Build & Run

1. Setup maven
2. Build Project
3. Run

### Setup maven
Requires Java 1.8+ and Maven 3.x+

1. Download maven from <https://maven.apache.org/download.cgi> and extract it.
2. Install JDK 8 and setup JAVA_HOME
3. Add maven bin directory to PATH 

### Build Project
Ensure java and maven are setup then run the following: 

```` bash
mvn initialize

mvn clean package
````
### Run

```
usage: Software_Forensic_Kit [-h] [-u <USERNAME>] [-p <PASSWORD>] [-d <DOMAIN>] [-f <FILTER>] [-s <FUNCTION>] 
	[-cd <NUM>] [-rp <arg>] [-rd] [-pp] [-g] [-gm] [-i] [-im] [-o <FOLDER>]

	 -h,--help
	 -u,--username <USERNAME>			Remote server username
	 -p,--password <PASSWORD>			Remote server password
	 -d,--domain <DOMAIN>				Remote server ip
	 -f,--filter <FILTER>				Jar path must contain this term to be included
	 -s,--searchFunction <FUNCTION>		Function to search for
	 -cd,--depth <NUM>					Max callgraph depth (default is 8)
	 -rp,--removePrefix <arg>			Remove Prefix from callgraph text
	 -rd,--removeDuplicates				Remove Duplicate Paths
	 -pp,--prettyPrint					Print output to console
	 -g,--graphVizM						Output for Graphviz
	 -gm,--graphVizM					Output for Graphviz Multiple
	 -i,--html							Output for HTML - https://visjs.org
	 -im,--htmlM 						Output for HTML Multiple -https://visjs.org
	 -o,--output <FOLDER>             Output to folder
```

Example Usage:

```
>java -jar software_forensic_kit-0.0.1-SNAPSHOT-all.jar -u root -d 10.123.157.145 -p test123 -s "ExampleClass:functionA" -f /var/www -im -rp my.class.path.
```

or using wildcards * for filter

```
>java -jar software_forensic_kit-0.0.1-SNAPSHOT-all.jar -u root -d 10.123.157.145 -p test123 -s "ExampleClass*functionA" -f /var/www -pp -rp my.class.path. -o C:\test\output
```

or locally using

```
>java -cp software_forensic_kit-0.0.1-SNAPSHOT-all.jar com.vmware.software_forensic_kit.java_gadget.Java_Gadget -s \"ExampleClass:functionA\" -im -rp my.class.path.  /home/test/testfile.jar\r\n" + 
```


## Contributing

The software-forensic-kit project team welcomes contributions from the community. If you wish to contribute code and you have not
signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any
questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq). For more detailed information,
refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
software-forensic-kit is available under the BSD-2 License.
For more detailed information, refer to [LICENSE.txt](LICENSE.txt).