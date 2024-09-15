# JCShell

This is the first assignment if my operating system course in the university.  The goals of this programming assignment were to have hands-on practice in designing and developing a shell program, which involves the creation, management, and coordination of multiple processes; and to learn how to use various important Unix system functions including to perform process creation and program execution, to support interaction between processes by using signals and pipes, and to get the processes’ running statistics by reading the /proc file system.


### Interactive Job Submission Program
Shell program, commonly known as a command interpreter, is a program that acts as the user interface to the Operating System and allows the system to understand your requests. Interactive job submission program, on the other hand, is implemented to be able to
1. Accpet a single command or a job that consists of a sequence of commands linked together with pipes (|) and executes the corresponding command(s) with the given argument list(s).
2. Locate and execute any valid program (i.e., compiled programs) by giving an absolute path (starting with /) or a relative path (starting with ./ or ../) or by searching directories under the $PATH environment variable.
3. Be terminated by the built-in exit command but it cannot be terminated by the Cltr-c key or the SIGINT signal.
4. Print the running statistics of all terminated command(s) and waits for the next command/job from the user, after the submitted command/job terminated.


### Implementation Workflow (My Tasks)
1. Create the first version of the JCshell program, which
   1. accepts an input line (contains a command and its arguments) from the user, 
   2. creates a child process to execute the command, 
   3. waits for the child process to terminate, 
   4. check the exit status of the child process,  
   5. prints the running statistics and the exit status of the terminated child process,
   6. prints in the output if the process is terminated by a signal, and
   7. prints the shell prompt and waits for the next command from the user after the child process terminated.
2. Modify previous version of the JCshell program to allow it to 
   1. handle the SIGINT signal correctly, 
   2. use the SIGUSR1 signal to control the child process, and 
   3. terminate the JCshell program when the user enters the exit command.
3. Modify previous version of the JCshell program to allow it to
   1. accept no more than 5 commands with/without arguments and the commands are separated by the ‘|’ symbol,
   3. wait for all commands to complete first before printing the running statistics of each terminated command, and
   4. print the running statistics of each terminated command according to their order of termination.



## Test and Result
This JCShell is tested and the results are printed in the Test.txt showing the implementation is successful.

#### Here is a summary of the information in the output.
1. PID The process ID of the terminated process
2. CMD The filename of the command – obtain from /proc/{pid}/stat or /proc/{pid}/status
3. STATE The process state (for our application, it is always in Zombie (Z) state) – obtain from
/proc/{pid}/stat or /proc/{pid}/status
4. EXCODE The exit code of the terminated process – obtain from /proc/{pid}/stat or from
waitpid()
5. EXSIG The name of the signal that caused the process to terminate
6. . PPID The process’s parent ID – obtain from /proc/{pid}/stat or /proc/{pid}/status
7. USER The amount of time (in seconds) the process was in user mode – obtain from
/proc/{pid}/stat
8. SYS The amount of time (in seconds) the process was in kernel mode – obtain from
/proc/{pid}/stat
9. VCTX The number of voluntary context switches experienced by the process – obtain from
/proc/{pid}/status
10. NVCTX The number of non-voluntary context switches experienced by the process – obtain
from /proc/{pid}/status
