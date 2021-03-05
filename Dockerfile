#HOW TO BUILD
#docker build -t software-forensic-kit .

FROM centos:7
RUN yum -y update 
RUN yum -y group install 'Development Tools' 
RUN yum -y install java-1.8.0-openjdk wget java-1.8.0-openjdk-devel
RUN wget https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz
RUN tar xvf apache-maven-3.6.3-bin.tar.gz && mv apache-maven-3.6.3  /usr/local/apache-maven && export M2_HOME=/usr/local/apache-maven && export M2=$M2_HOME/bin && export PATH=$M2:$PATH && export JAVA_HOME=$(find /usr/lib/jvm -name "*java*openjdk-*") && source ~/.bashrc
COPY . /software_forensic_kit
#FIRST ADD TOOLS AS A JAR IN LOCAL REPOSITORY
RUN cd /software_forensic_kit && export JAVA_HOME=$(find /usr/lib/jvm -name "*java*openjdk-*") && /usr/local/apache-maven/bin/mvn install:install-file -Dfile="${JAVA_HOME}/lib/tools.jar" -DgroupId=com.sun -DartifactId=tools -Dversion=1.8.0 -Dpackaging=jar &&  /usr/local/apache-maven/bin/mvn  install -X 
RUN cp software_forensic_kit/target/software_forensic_kit-0.0.1-SNAPSHOT-jar-with-dependencies.jar /tmp/software_forensic_kit-0.0.1-SNAPSHOT-jar-with-dependencies.jar

#docker run -it -d --privileged software-forensic-kit:latest /usr/sbin/init
#docker exec -it <container> /bin/bash
#docker cp <container>:/tmp/software_forensic_kit-0.0.1-SNAPSHOT-jar-with-dependencies.jar ./software_forensic_kit-0.0.1-SNAPSHOT-jar-with-dependencies.jar