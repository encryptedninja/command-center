# Buffer Overflow (Basic)

**[Back To Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**

**You can find all the necesarry files in the `scripts` folder.**

## Things you'll need

* need a Windows machine on a VM (get it for free from Google: Microsoft Evaluation Center)
* download and install **Immunity Debugger** (goes on the Win machine): **[Download Link](https://debugger.immunityinc.com/ID_register.py)** and here's the **[Main Website](https://www.immunityinc.com/products/debugger/)**
* download from Github: **[mona](https://github.com/corelan/mona)** and put it in the 
* kali of course
* scripts from the **`./scripts`** folder

## Quick Visual Recap

* In the Stack we are overflowing the buffer space to reach the **EIP**
* We can use the **EIP** to point into directions that we instruct

![1-anathomy-of-the-memory](images/1-anatomy_of_the_memory.png)
![2-anatomy_of_the_stack](images/2-anatomy_of_the_stack.png)
![3-overflow](images/3-overflow.png)

## Spike and Fuzzing
