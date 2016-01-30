# SP15MP1
#### Student ID
b03902015
#### Program Usage
In this homework, I practice the fundamental IO functions via implementing part of the most important feature in version control systems including git, the merge function.

When multiple developers are working on the same project, they can create branch of the project to work on them independently and merge the branches back into the same branch later. The merge function thus has to deal with difference and conflicts on edited files.

My program finds the difference of two files and output the merged result to another file. The merge function will compare the two input files line by line, copies the common lines to the output file, and shows the conflicted lines to the output file if there is any.
#### Sample execution
###### Compile  
make -C src clean  
make -C src
###### Run  
./bin/file_merger test/ex1_1 test/ex1_2 test/ex1_log  
###### Check result  
diff test/ex1_3 test/ex1_log
