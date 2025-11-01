# My Learning Journey

To be honest: This is my first kubebuilder project and I'm trying to learn how to develop my own Operatro with it.
I'm experienced in programming several languages, including go , but until know never wrote an Operator for k8s.

I would like to trace my journey a little bit within this file


## Remote Debugging

I never had a chance to get this to live without the help of https://telepresence.io/.
The experince to debug my go code full integrated in the kubernetes reconcillation loop was awesome.

If you woul like todo something similar, you might find this link helpfull:
https://ttt.io/kubernetes-admission-controller


## TODOs

1.) I didn't care for the unit tests. Shame over me 

2.) I realized, that kubebuilder generates all kubernestes manifstes, after I create my own helm chart 