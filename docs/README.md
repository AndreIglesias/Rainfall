<h1 align="center">
  Rainfall
</h1>
<p align="center">
    <img src = "https://user-images.githubusercontent.com/35022933/213947145-70f02ba3-4a0f-41ee-9c75-bf24c6d18aba.png" width = "50%"> 
</p>

## Levels summary


<details>
<summary><b>Level 0</b></summary
<br/>&emsp;
<b>Objective:</b> Binary analysis to find out which number we have to input (<b>423</b>).
<br/>&emsp;
<a href="../level0/walkthrough.md">Walkthrough.md</a>

```C
int main(int argc, const char **argv, const char **envp)
{
    if (atoi(argv[1]) != 423)
    {
        // Write "No !" to stderr
        fwrite("No !\n", sizeof(char), 5, stderr);
    } 
    else 
    {
        // Execute /bin/sh
        char *shell_cmd = strdup("/bin/sh");
        setresgid(getegid(), getegid(), getegid());
        setresuid(geteuid(), geteuid(), geteuid());
        execv(shell_cmd, argv);
    }
    return (0);
}
```
</details>
<details>
<summary><b>Level 1</b></summary
<br/>&emsp;
<b>Objective:</b> Buffer overflow on <b><i>gets</i></b> function, to overwritte the <b>EIP</b> reg to point to the <b><i>run</i></b> function.
<br/>&emsp;
<a href="../level1/walkthrough.md">Walkthrough.md</a> <a href="../level1/walkthrough_pwntools.md">Walkthrough_pwntools.md</a>

```C
void run() {
    FILE *stdout_ptr = stdout;

    // Print the message "Good... Wait what?\n" to the standard output
    fwrite("Good... Wait what?\n", sizeof(char), 17, stdout_ptr);

    // Execute the "/bin/sh" shell command
    system("/bin/sh");
}
int main(int argc, const char **argv, const char **envp)
{
    char buffer[??]; // Buffer to hold user input
    
    gets(buffer); // Reading input from the user

    return 0;
}
```
</details>
<details>
<summary><b>Level 2</b></summary
<br/>&emsp;
<b>Objective:</b> Buffer overflow on <b><i>gets</i></b> function, to inject <i>shellcode</i> into the <i>Heap</i>, and execute it overwriting the <b>EIP</b> reg to point to the code on the <i>Heap</i>.
<br/>&emsp;
<a href="../level2/walkthrough.md">Walkthrough.md</a>

```C
int p()
{
  char buffer[64]; // ebp+0x4C - ebp+0xC
  int arg;
  int eax;
  int edx;

  fflush(stdout);   // Flush stdout buffer
  gets(buffer);     // Again, possible buffer overflow
  memcpy(eax, &buffer[80], 4);  // Copy EIP (return address) from buffer[80] to eax
  arg = &buffer[64];  // Set arg to point to the end of buffer
  memcpy(arg, eax, 4);  // Copy 4 bytes from eax to arg
  memcpy(eax, arg, 4);  // Copy 4 bytes from arg to eax
  if ( (eax & 0xB0000000) == 0xB0000000 )
  {
    printf("(%p)\n", arg);
    exit(1);
  }
  puts(buffer);
  return (strdup(buffer));
}
int main(int argc, const char **argv, const char **envp)
{
  return (p());
}
```
</details>
<details>
<summary><b>Level 3</b></summary
<br/>&emsp;
<b>Objective:</b> Format string attack on <b><i>printf</i></b> function, to inject the number <i>64</i> into the global variable <b><i>m</i></b>.
<br/>&emsp;
<a href="../level3/walkthrough.md">Walkthrough.md</a>

```C
int m = 0;

int v() {
    int result;         // EAX
    char buffer[520];   // [esp+10h] [ebp-208h] BYREF
    fgets(buffer, 512, stdin);  // Read up to 512 characters from stdin
    printf(buffer); // Print the buffer
    result = m;
    if (m == 64) {  // @
        fwrite("Wait what?!\n", 1, 12, stdout);
        return (system("/bin/sh"));
    }
    return (result);
}
int main() {
    return (v());
}
```
</details>
<details>
<summary><b>Level 4</b></summary
<br/>&emsp;
<b>Objective:</b> Format string attack on <b><i>printf</i></b> function, to inject the number <i>16930116</i> into the global variable <b><i>m</i></b>.
<br/>&emsp;
<a href="../level4/walkthrough.md">Walkthrough.md</a>

```C
int m = 0;

int p(int buffer) {
    return (printf(buffer));
}
int n()
{
  int eax;      // EAX
  char v1[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(v1, 512, stdin);
  p(v1);
  eax = m;
  if ( m == 16930116 )
    return system("/bin/cat /home/user/level5/.pass");
  return eax;
}
int main() {
    int eax;

    n();
    return (eax);
}
```
</details>
<details>
<summary><b>Level 5</b></summary
<br/>&emsp;
<b>Objective:</b> Format string attack on <b><i>printf</i></b> function, to hijack the <b>Global Offset Table</b> replacing there the <b><i>exit</i></b> address for the <b><i>o()</i></b> function address to redirect the code execution.
<br/>&emsp;
<a href="../level5/walkthrough.md">Walkthrough.md</a>

```C
int n()
{
  char v4[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(v4, 512, stdin);
  printf(v4);
  exit(1);
}
int o()
{
  system("/bin/sh");
  _exit(1);
}
int main() {
    return (n());
}
```
</details>
<details>
<summary><b>Level 6</b></summary
<br/>&emsp;
<b>Objective:</b> Buffer overflow on <b><i>strcpy</i></b> function, to overwrite the <b>EIP</b> (which was going to execute <b><i>m()</i></b>) to make it execute <b><i>n()</i></b> instead.
<br/>&emsp;
<a href="../level6/walkthrough.md">Walkthrough.md</a>

```C
int n()
{
  return (system("/bin/cat /home/user/level7/.pass"));
}
int m()
{
  return (puts("Nope"));
}
int main(int argc, const char **argv, const char **envp)
{
  int (**v4)(void); // [esp+18h] [ebp-8h]
  int v5; // [esp+1Ch] [ebp-4h]

  v5 = malloc(64);
  v4 = (int (**)(void))malloc(4);
  *v4 = m;
  strcpy(v5, argv[1]);
  return ((*v4)());
}
```
</details>
<details>
<summary><b>Level 7</b></summary
<br/>&emsp;
<b>Objective:</b> Buffer overflow on the 2 <b><i>strcpy</i></b> functions, to hijack the <b>Global Offset Table</b> replacing there the <b><i>puts</i></b> address for the <b><i>m()</i></b> function address to redirect the code execution and print the <b><i>.pass</i></b> content.
<br/>&emsp;
<a href="../level7/walkthrough.md">Walkthrough.md</a>

```C
char *c = NULL;

int m()
{
  int eax;

  eax = time(0);
  return printf("%s - %d\n", c, eax);
}
int main(int argc, const char **argv, const char **envp)
{
  int eax; // eax
  _DWORD *v5; // [esp+18h] [ebp-8h]    argv[2]
  _DWORD *v6; // [esp+1Ch] [ebp-4h]    argv[1]

  v6 = (_DWORD *)malloc(8);
  *v6 = 1;
  v6[1] = malloc(8);
  v5 = (_DWORD *)malloc(8);
  *v5 = 2;
  v5[1] = malloc(8);
  strcpy(v6[1], argv[1]); // Vulnerable for buffer overflow
  strcpy(v5[1], argv[2]); // Vulnerable for buffer overflow
  eax = fopen("/home/user/level8/.pass", "r");
  fgets(&c, 68, eax); // 68 is the lenght of the flag from .pass
  // c has now the flag
  puts("~~"); // Call m() instead of puts()
  return 0;
}
```
</details>
<details>
<summary><b>Level 8</b></summary
<br/>&emsp;
<b>Objective:</b> play with the options of the program to write at the <i>32th</i> byte of the <b><i>auth</i></b> global variable.
<br/>&emsp;
<a href="../level8/walkthrough.md">Walkthrough.md</a>

```C
char *auth = NULL;
char *service = NULL;

int main(int argc, const char **argv, const char **envp)
{
  char *input;

  while ( 1 )
  {
    printf("%p, %p \n", auth, service);
    if ( !fgets(input, 128, stdin) )
      break;
    if ( !memcmp(input, "auth ", 5u) )
    {
      auth = malloc(4);
      *auth = 0;
      if ( strlen(input + 5) <= 30 )
        strcpy(auth, input + 5);
    }
    if ( !memcmp(input, "reset", 5u) )
      free(auth);
    if ( !memcmp(input, "service", 6u) )
      service = strdup(input + 7);
    if ( !memcmp(input, "login", 5u) )
    {
      if ( auth[32] )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1, 10, stdout);
    }
  }
  return 0;
}
```
</details>
<details>
<summary><b>Level 9</b></summary
<br/>&emsp;
<b>Objective:</b> Buffer overflow on c++ object with <i><b>memcpy</b></i> to overwrite the vtable of a second object on the <b>heap</b>.
<br/>&emsp;
<a href="../level9/walkthrough.md">Walkthrough.md</a>

```C
class N {
public:
    char buffer[100];
    int value;

    N(int value) : value(value) {}

    void setAnnotation(char* annotation) {
        int len = strlen(annotation);

        std::memcpy(this->buffer, annotation, len);
    }

    int operator+(const N &right) const {
        return (this->value + right.value);
    }

    int operator-(const N &right) const {
        return (this->value - right.value);
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        exit(1);
    }

    N* instance1 = new N(5);
    N* instance2 = new N(6);

    instance1->setAnnotation(argv[1]);

    return (*instance2 + *instance1);
}
```
</details>
