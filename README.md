# Reviving Netalyzr

Reviving Netalyzr ( https://www.netalyzr.berkeley.edu/ shutdown as of 2019), the ICIR seem to have no plans to open source or revive Netalzyr themselves. This is unfortunate as it really did thousands of users diagnose internet related users - for free.
In return  the authors got data - lots of data at one point 20-70 new sessions per hour. This was pretty early and the database was already over 180gb.

We are taking a look at how or if we can revive Netalyzr, one of the most comprehensive internet checks/tests for the end user.

The main file that runs the test is:
Netalyzr.java

The idea of this project will be to either rewrite the Netalyzr totally or get the old client working.

# Where we currently stand.
So far after taking a look at the java client, we have managed to access all the client-side code. We can now direct all the checks made to a server - somewhere other than berkley or icir.

Each test performed by the client looked for certain replies from the server to verify the result.

We know that the server-side was made in python and it replied to the client in various protocols, which include HTTP ECHO, and custom protocol names.

A simple ECHO server with IP:PORT give the client a baseline to connect to.

# Known steps the client takes.

1.Looks for a config served as plain text this includes
  -Build number
  -The node the test will be performed on
  -The ID given to the client to run the test
  -Various other details (see config.txt)

2. Tests are then generated and start running.

# Needed.

-Server, we have currently used a simple phython echo server to get the client repsonding to the test. This needs to be worked on to get more of the tests working.

Full packet log(pcap) of the netalyzr app was found at:
https://www.packettotal.com/app/analysis?id=3cf9484474fada458a16e179f6a87493&__cf_chl_captcha_tk__=d24d7a016687267b465732e3233bf192e5adbd21-1616175519-0-AZWHEhvL86vxDnLDhsbaPJzXWlHLExy5GCBe1OvOOpn3JU5BlsGLJxmZafUby7XrsXeEbhiotVQvz5omtVcx1kBOXOyfu28QTZj1J1qIUnG_S8aq1MNmXXsCDYUAYl_VBwvfxgP4HICDAqntECxg7TsaZwYSE0ymseWsViFOOdN5_kPg5ASmU5h86Gv328a0s9lDucuS0rx3MB_KypkL3KU2RYXABwwxE6Hr3Xx-1Nc9-fu0kWg3hImCtBxtrsfLHmf8ELR5Z3fGwwTxa8ewAu-LAzgDmzEpZA1wiCjqKziL6mX6Upyoq9mqAr9pOAsKl_pjXkTwkqlsZlYoUBDKNxr0vXGX23zE81pDnFbf3PvxKOi2JYIf-htT9D-xPFAaH1HxnBVo_-wR8aN9wYXZTZ1UUcBHsO_O1p73l6_lC7AxioWvq1qibw3boNlYzf75hZrUfgCn251ie1HBuzSO2puqfMo5vD1O9d6_jB9H5iTNPboALUoXqRrRMt-6dv_9rBalqCyJDwH6q9zNK4IneJuv7wlIrLztkXGTtEdnz4i2-CdtFDSZsuOjDe8ZDbI2zXjujR9TFutfBdLF0yzJFXXes5Un96H4QjHc_MwXeeau

If you think you can help email ifatuus@neoxios.com
