# JavaMongo

Demonstration code for interacting with MongoDB Using Java

Copyright (C) 2016 David S. Read

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/

For information Dave's MongoDB educational materials: https://www.monead.com/nosql/
For information on MongoDB: https://www.mongodb.com/


## Running the Default Sample Program

The project is setup to run using Apache Ant.

1) Import the sample honeypot data described at [https://monead.com/nosql/]

2) Make sure that __MongoDB__ is running on port __27017__ (the default)

3) Open a terminal and change your working direcory to the project home directory containing the __build.xml__ file

4) Type the command: 
```
ant run
```


## Generating the JavaDoc for the project

1) Open a terminal and change your working direcory to the project home directory containing the __build.xml__ file

2) Type the command: 
```
ant javadoc
```

## Run the unit tests and review the results (including code coverage)

1) Open a terminal and change your working directory to the project home directory containing the __build.xml__ file

2) Type the command: 
```
ant test
```

3) To view the test results use your browser to open the file: __generated/reports/unit-test/index.html__

4) To view the code coverage results use your browser to open file: __generated/reports/cobertura/index.html__

