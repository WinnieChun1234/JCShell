/* 
    Development plaform: Visual Studio Code, Docker and workbench
    Remark: I finished all the requirements
*/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>

#define MAX_ARGS_INPUT 30   // max strings from input
#define MAX_CHAR_INPUT 1024 // max characters from input
#define MAX_COMM_INPUT 5     // max command from input
#define ERROR_EXIT_CODE 84
#define CONSECUTIVE_PIPE_ERROR "JCshell: should not have two | symbols without in-between command\n" 
#define INCOMPLETE_PIPE_SEQUENCE_ERROR "JCshell: Incomplete | sequence\n" 
#define ERR_MSG_HEAD "JCshell: " 

struct infoStructure{ // struct for storing the process statistics 
    int PID;
    char CMD[50];
    char STATE;
    int EXCODE;
    char EXSIG[50];
    int PPID;
    float USER;
    float SYS;
    int VCTX;
    int NVCTX;
};
struct infoStructure temp; // for storing temporary statistics of each run process
struct infoStructure arrayOfinfoStructure[5]; // for storing all process statistics struct

char input[MAX_CHAR_INPUT + 1]; // to store the input string; plus 1 to handle the newline character
char* tokenizedArguments[MAX_COMM_INPUT][MAX_ARGS_INPUT + 1];  //to store the tokenized arguments; plus 1 for adding null to handle vector structure for exec()
int toExit = 0; //counter to indicate when to prompt user again
pid_t childpid[5]; 
pid_t childstatus[5];
pid_t parentpid;
int noOfChild = 0;
int usr_interrupt = 0; 
int pipefd_1[2]; //file descripter for the pipe1
int pipefd_2[2]; //file descripter for the pipe2
int pipefd_3[2]; //file descripter for the pipe3
int pipefd_4[2]; //file descripter for the pipe4
int createdChild = 0;
int isInput = 0; 


char *signal_list[] = { //copied header from tutorial 
    "NULL", // 0 - NULL, not used
    "SIGHUP", // 1
    "SIGINT", // 2
    "SIGQUIT", // 3
    "SIGILL", // 4
    "SIGTRAP", // 5
    "SIGABRT", // 6
    "SIGBUS", // 7
    "SIGFPE", // 8
    "SIGKILL", // 9
    "SIGUSR1", // 10
    "SIGSEGV", // 11
    "SIGUSR2", // 12
    "SIGPIPE", // 13
    "SIGALRM", // 14
    "SIGTERM", // 15
    "SIGSTKFLT", // 16
    "SIGCHLD", // 17
    "SIGCONT", // 18
    "SIGSTOP", // 19
    "SIGTSTP", // 20
    "SIGTTIN", // 21
    "SIGTTOU", // 22
    "SIGURG", // 23
    "SIGXCPU", // 24
    "SIGXFSZ", // 25
    "SIGVTALRM", // 26
    "SIGPROF", // 27
    "SIGWINCH", // 28
    "SIGIO", // 29
    "SIGPWR", // 30
    "SIGSYS", // 31
};
char *signal_des[] = { //copied header from tutorial 
    "NULL", // 0 - NULL, not used
    "Hangup", // 1
    "Interrupt", // 2
    "Quit", // 3
    "Illegal instruction", // 4
    "Trace trap", // 5
    "Abort", // 6
    "Bus error", // 7
    "Floating point exception", // 8
    "Killed", // 9
    "User defined signal 1", // 10
    "Segmentation fault", // 11
    "User defined signal 2", // 12
    "Broken pipe", // 13
    "Alarm clock", // 14
    "Software termination signal", // 15
    "Stack fault", // 16
    "Child status has changed", // 17
    "Continue", // 18
    "Stop", // 19
    "Keyboard stop", // 20
    "Background read from tty", // 21
    "Background write to tty", // 22
    "Urgent condition on socket", // 23
    "Cpu time limit exceeded", // 24
    "File size limit exceeded", // 25
    "Virtual alarm clock", // 26
    "Profiling alarm clock", // 27
    "Window size change", // 28
    "I/O now possible", // 29
    "Power failure", // 30
    "Bad system call", // 31
};

// to prompt with process ID
int promptWithPID(){
    // to prompt with process ID
    printf("## JCshell [%d] ##  ", parentpid); 
    return 0;
}

// to get input and check for errors
int getInput(){
    // to get the input using fgets() 
    isInput = 1;
    fgets(input, sizeof(input), stdin);
    isInput = 0;
    // to handle the consecutive '|' error
    for (int i = 0; input[i] != '\0' ; i++){ //loop until the end of the input string
        if (input[i] == '|' ) { // if there is '|'
            if ( input[i+1] == '|') { // and if there is '|' on the next
                printf(CONSECUTIVE_PIPE_ERROR); //consecutive error
                return -1; // return value for later error printing
            }else{ // if not '|' on the next
                int spaceCount = 1; 
                while (input[i+spaceCount] == ' ' ){ //loop and add 1 to the counter spaceCount to check if the next are ' '
                    spaceCount++;
                } // the loop stops when no ' ' found
                if (input[i+spaceCount] == '|'){ //if there is '|' on the next
                    printf(CONSECUTIVE_PIPE_ERROR); //consecutive error
                    return -1;
                }
            }
        }
    }
    // to remove the newline character at the end of the input
    input[strcspn(input, "\n")] = '\0';
    // to handle the '|' error at the start and the end
    if ((input[0] == '|') || (input[strlen(input)-1] == '|')) {
        printf(INCOMPLETE_PIPE_SEQUENCE_ERROR);
        return -2;
    }

    return 0;
}

/*  to tokenize input and return an array of arguments */
int getTokenizedInput(){ 

    // to separate the command by pipe
    char* commandToken = strtok(input, "|");
    // to count how many command are there
    int comCount = 0;
    // an array sized with MAX_COMM_INPUT to store the command string
    char * tokenCommands[MAX_COMM_INPUT];
    // while there is command and not exceeding the max limit, append the command to the array and do next
    while (commandToken != NULL && comCount < MAX_COMM_INPUT) {
        tokenCommands[comCount++] = commandToken;
        commandToken = strtok(NULL, "|");
    }

    int hasExitAtStart = 0; // counter to check if there is exit at the start of the first command
    
    // to tokenize the input by space
    for ( int i = 0; i < comCount; i++){
        // to count how many argumnets in one command
        int argCount = 0;
        char* token = strtok(tokenCommands[i], " ");
        // while there is token and not exceeding the max limit, append the command to the array and do next
        while (token != NULL && argCount < MAX_ARGS_INPUT) {
            // if there is "exit" in the token, and it is in the first argument, assign the counter of hasExitAtStart to be true
            if (( strcmp(token, "exit") == 0 ) && ( argCount == 0 )) { hasExitAtStart = 1; }
            tokenizedArguments[i][argCount++] = token;
            token = strtok(NULL, " ");
        }
        if ( (i == 0 ) && (hasExitAtStart == 1)) {
            if (argCount == 1){
                toExit = 1;
                printf("JCshell: Terminated\n");
                exit(0); 
            } else if (argCount > 1) {
                printf("JCshell: \"exit\" with other arguments!!!\n");
                return -3;
            }
        }
        
        // add a null pointer for complying the standard input for exec()
        tokenizedArguments[i][argCount++] = NULL;
    }


    return comCount;
}

// to create child process
int createChild(int num){
    pid_t childPID = fork();

    if (childPID < 0) {
        fprintf(stderr, "fork() Failed");
        exit(-1);
    } else if (childPID == 0) { //Child process
        
        if (num == 0){
            if ( createdChild > 1) { 
                dup2(pipefd_1[1], STDOUT_FILENO) ; // redirect stdout to the write end of pipe1
                close(pipefd_1[0]); // close the read end of pipe1
                close(pipefd_1[1]); // close the write end of pipe1
            }
        } else if (num == 1) {
            dup2(pipefd_1[0], STDIN_FILENO) ; // redirect stdout to the read end of pipe1
            close(pipefd_1[1]); // close the write end of pipe1
            close(pipefd_1[0]); // close the read end of pipe1
            if ( createdChild > 2) { 
                dup2(pipefd_2[1], STDOUT_FILENO) ; // redirect stdout to the write end of pipe1
                close(pipefd_2[0]); // close the read end of pipe2
                close(pipefd_2[1]); // close the write end of pipe2
            }
        }else if (num == 2 ){
            close(pipefd_1[1]); // close the write end of pipe1
            close(pipefd_1[0]); // close the read end of pipe1

            dup2(pipefd_2[0], STDIN_FILENO) ; // redirect stdout to the read end of pipe2
            close(pipefd_2[1]); // close the write end of pipe2
            close(pipefd_2[0]); // close the read end of pipe2
            if ( createdChild > 3) { 
                close(pipefd_3[0]); // close the read end of pipe3
                dup2(pipefd_3[1], STDOUT_FILENO) ; // redirect stdout to the write end of pipe3
                close(pipefd_3[1]); // close the write end of pipe3
            }
        }else if (num == 3 ){
            close(pipefd_1[1]); // close the write end of pipe1
            close(pipefd_1[0]); // close the read end of pipe1

            close(pipefd_2[1]); // close the write end of pipe2
            close(pipefd_2[0]); // close the read end of pipe2

            dup2(pipefd_3[0], STDIN_FILENO) ; // redirect stdout to the read end of pipe3
            close(pipefd_3[1]); // close the write end of pipe3
            close(pipefd_3[0]); // close the read end of pipe3
            if ( createdChild > 4) { 
                close(pipefd_4[0]); // close the read end of pipe4
                dup2(pipefd_4[1], STDOUT_FILENO) ; // redirect stdout to the write end of pipe4
                close(pipefd_4[1]); // close the write end of pipe4
            }
        }else if (num == 4 ){
            close(pipefd_1[1]); // close the write end of pipe1
            close(pipefd_1[0]); // close the read end of pipe1

            close(pipefd_2[1]); // close the write end of pipe2
            close(pipefd_2[0]); // close the read end of pipe2
            
            close(pipefd_3[1]); // close the write end of pipe3
            close(pipefd_3[0]); // close the read end of pipe3

            close(pipefd_4[1]); // close the write end of pipe4
            dup2(pipefd_4[0], STDIN_FILENO) ; // redirect stdout to the read end of pipe4
            close(pipefd_4[0]); // close the read end of pipe4

        }
        close(pipefd_1[1]); // close the write end of pipe1
        close(pipefd_1[0]); // close the read end of pipe1

        close(pipefd_2[1]); // close the write end of pipe2
        close(pipefd_2[0]); // close the read end of pipe2
        
        close(pipefd_3[1]); // close the write end of pipe3
        close(pipefd_3[0]); // close the read end of pipe3

        close(pipefd_4[1]); // close the write end of pipe4
        close(pipefd_4[0]); // close the read end of pipe4

        sigset_t mask, oldmask;
        // to set up the mask of signals to temporarily block
        sigemptyset (&mask);
        sigaddset (&mask, SIGUSR1);

        // to wait for signal arrive
        sigprocmask (SIG_BLOCK, &mask, &oldmask);
        while (!usr_interrupt)
            sigsuspend (&oldmask);
        sigprocmask (SIG_UNBLOCK, &mask, NULL);

        // to execute the command
        execvp(tokenizedArguments[num][0], tokenizedArguments[num]);
        

        // print error
        char combined[strlen(tokenizedArguments[num][0]) + strlen(ERR_MSG_HEAD)];
        strcpy(combined, ERR_MSG_HEAD);
        strcat(combined, "'");
        strcat(combined, tokenizedArguments[num][0]);
        strcat(combined, "'");
        perror(combined);

        exit(ERROR_EXIT_CODE); //to tell parent the child exit with error

    } else { //Parent Process
        childpid[noOfChild] = childPID;
        noOfChild++; 

    }
    return 0;
}

// signal handler for parent signal
void siganlHandler(int signum){
    usr_interrupt = 1;
}

// signal handeler for interrupt
void signalInterruptHandler(int signum){
     if (isInput == 1){
        printf("\n");
        promptWithPID();
        fflush(stdout);
     }
}

void debugFuntion(){ // to print out the whole array
    printf("Arguments for debug:\n");
    for (int i = 0; i < MAX_COMM_INPUT; i++) {
        printf("%i\n", i);
        for (int j = 0; j < MAX_ARGS_INPUT; j++)
            printf("%s\n", tokenizedArguments[i][j]);
    }
}

void saveChildStat(pid_t childpid){ // to find and save required items from the statistics, referring to tutorial
    char str[50];
	char CMD[50]; // command name
	FILE * file;
	int foo_int; // placeholder for a number(4byte) we don't care in a fomrat string
    int PID;
    int PPID;
    float USER;
    float SYS;

	unsigned long long i, x;
	unsigned long h, ut, st;

	/* get my own procss statistics */
	sprintf(str, "/proc/%d/stat", (int)childpid);
	file = fopen(str, "r");
	if (file == NULL) {
		printf("Error in open my proc file\n");
		exit(0);
	}
	// read first 15 fields
	fscanf(file, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu",
           &PID, CMD, &str[0], &PPID, &foo_int, &foo_int, &foo_int, &foo_int,
		(unsigned *)&foo_int, &h, &h, &h, &h, &ut, &st);
	fclose(file);
    USER = ut*1.0f/sysconf(_SC_CLK_TCK);
    SYS = st*1.0f/sysconf(_SC_CLK_TCK);

    temp.PID = PID;
    temp.PPID = PPID;
    temp.USER = USER;
    temp.SYS = SYS;
    temp.STATE = str[0];
    
}

void saveChildStatus(pid_t childpid){ // to find and save required items from the status, referring to tutorial
    char str[50];
	FILE * file;
    int VCTX;
    int NVCTX;
    char CMD[50];

	unsigned long long i, x;
	unsigned long h, ut, st;

	/* get my own procss statistics */
	sprintf(str, "/proc/%d/status", (int)childpid);
	file = fopen(str, "r");
	if (file == NULL) {
		printf("Error in open my proc file\n");
		exit(0);
	}
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "voluntary_ctxt_switches: %d", &VCTX) == 1) { 
        } else if (sscanf(line, "nonvoluntary_ctxt_switches: %d", &NVCTX) == 1) {
        } else if (sscanf(line, "Name: %s", CMD) == 1) {
        }
    }
	fclose(file);

    temp.VCTX = VCTX;
    temp.NVCTX = NVCTX;
    strcpy(temp.CMD, CMD);

}

void saveChildInfo(){ // to find and save required items 
    siginfo_t info;
    int status;
    pid_t myid;
    int EXCODE;
    int EXSIG;

    // wait for child to terminate and kept as zombie process
    // 1st param: P_ALL := any child process; P_PID := process specified as 2nd param
    // WNOWAIT: Leave the child in a waitable state;
    //    so that later another wait call can be used to again retrieve the child status information.
    // WEXITED: wait for processes that have exited
    int ret = waitid(P_ALL, 0, &info, WNOWAIT | WEXITED);  
    if (!ret) {
        saveChildStat(info.si_pid);
        saveChildStatus(info.si_pid);

        waitpid(info.si_pid, &status, 0);

    // printf("Child process %d's resource has been clean\n", (int) info.si_pid);
        if (WIFEXITED(status)) {
            EXCODE = WEXITSTATUS(status); 
            temp.EXCODE = EXCODE;
            strcpy(temp.EXSIG, "not kiled");
        }else if (WIFSIGNALED(status)) { // check if is killed
            EXSIG =  WTERMSIG(status);
            strcpy(temp.EXSIG, signal_des[EXSIG]);
        }
    } else {
      perror("waitid");
    }
}

void printInfo(struct infoStructure infoStruct){ // to print the statistcis
    if (strcmp(infoStruct.EXSIG,"not kiled")==0) {
        if (infoStruct.EXCODE == ERROR_EXIT_CODE) {
            return;
        }
        printf("(PID)%d (CMD)%s (STATE)%c (EXCODE)%d (PPID)%d (USER)%.2f (SYS)%.2f (VCTX)%d (NVCTX)%d\n", 
        infoStruct.PID, infoStruct.CMD, infoStruct.STATE, infoStruct.EXCODE, 
        infoStruct.PPID, infoStruct.USER, infoStruct.SYS, infoStruct.VCTX, infoStruct.NVCTX);
    }else{
        printf("(PID)%d (CMD)%s (STATE)%c (EXSIG)%s (PPID)%d (USER)%.2f (SYS)%.2f (VCTX)%d (NVCTX)%d\n", 
        infoStruct.PID, infoStruct.CMD, infoStruct.STATE, infoStruct.EXSIG, 
        infoStruct.PPID, infoStruct.USER, infoStruct.SYS, infoStruct.VCTX, infoStruct.NVCTX);
    }
}

int main(int argc, char *argv[]) {
    // Set up signal handler for SIGNINT
    signal(SIGINT, signalInterruptHandler); // Set handler for signal interrupt
    signal(SIGUSR1, siganlHandler); //Set handler for user defined signal; when the program recieve SIGUSR1, it will involve signalHandler()

    while ( toExit == 0 )
    {
       
        parentpid = getpid(); 
        promptWithPID();
        int errorValue = getInput(); // run getInput() and check return value
        if ( errorValue < 0 ){continue;} 
        int toBeCreatedChild = getTokenizedInput();

        if (toBeCreatedChild < 0){continue;}
        noOfChild = 0;
        createdChild = toBeCreatedChild; //copy value of toBeCreatedChild to the global variable createdChild

        if ((pipe(pipefd_1)  == -1 ) || (pipe(pipefd_2)  == -1 ) || (pipe(pipefd_3)  == -1 ) || (pipe(pipefd_4)  == -1 )){ //create pipe
            // perror("pipe");
        }
        for (int i = 0; i < toBeCreatedChild; i++){
            signal(SIGUSR1, siganlHandler); //Set handler for user defined signal; when the program recieve SIGUSR1, it will involve signalHandler()
            createChild(i);
        }

        // close all pipes
        close(pipefd_1[0]);
        close(pipefd_1[1]);
        close(pipefd_2[0]);
        close(pipefd_2[1]);
        close(pipefd_3[0]);
        close(pipefd_3[1]);
        close(pipefd_4[0]);
        close(pipefd_4[1]);

        for (int i = 0; i < noOfChild; i++){
            kill(childpid[i], SIGUSR1);  //Send signal to child and resume them      
        }

        for(int i = 0; i < noOfChild; i++ ){ //save the stat of each child created to the temp struct & clear it
            saveChildInfo();
            arrayOfinfoStructure[i] = temp;
            memset(&temp, 0, sizeof(struct infoStructure));
        }
        
        for(int i = 0; i < noOfChild; i++ ){ //print all stat of the child
            printInfo(arrayOfinfoStructure[i]);
        }
        continue;   
    }
    return 0;
}