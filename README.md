# netalyzr

Netalyzr ( https://www.netalyzr.berkeley.edu/ ) shutdown as of 2019.

After finding the old command line client, and using a decompiler these are the files that remain.
Perhaps someonme will be able to recreate or fix the java application it was one of the most useful and extensive internet diagnostic tools online.

Currently the application wants to report home to https://netalyzr.icsi.berkeley.edu/analysis/m=cli and expects a http code 200(OK) at the endpoint to move on with the test.
Which at berkleys side was later moved to	https://n1.netalyzr.icsi.berkeley.edu/analysis/m=cli/l=en-US

Full packet log(pcap) of the netalyzr app was found at:
https://www.packettotal.com/app/analysis?id=3cf9484474fada458a16e179f6a87493&__cf_chl_captcha_tk__=d24d7a016687267b465732e3233bf192e5adbd21-1616175519-0-AZWHEhvL86vxDnLDhsbaPJzXWlHLExy5GCBe1OvOOpn3JU5BlsGLJxmZafUby7XrsXeEbhiotVQvz5omtVcx1kBOXOyfu28QTZj1J1qIUnG_S8aq1MNmXXsCDYUAYl_VBwvfxgP4HICDAqntECxg7TsaZwYSE0ymseWsViFOOdN5_kPg5ASmU5h86Gv328a0s9lDucuS0rx3MB_KypkL3KU2RYXABwwxE6Hr3Xx-1Nc9-fu0kWg3hImCtBxtrsfLHmf8ELR5Z3fGwwTxa8ewAu-LAzgDmzEpZA1wiCjqKziL6mX6Upyoq9mqAr9pOAsKl_pjXkTwkqlsZlYoUBDKNxr0vXGX23zE81pDnFbf3PvxKOi2JYIf-htT9D-xPFAaH1HxnBVo_-wR8aN9wYXZTZ1UUcBHsO_O1p73l6_lC7AxioWvq1qibw3boNlYzf75hZrUfgCn251ie1HBuzSO2puqfMo5vD1O9d6_jB9H5iTNPboALUoXqRrRMt-6dv_9rBalqCyJDwH6q9zNK4IneJuv7wlIrLztkXGTtEdnz4i2-CdtFDSZsuOjDe8ZDbI2zXjujR9TFutfBdLF0yzJFXXes5Un96H4QjHc_MwXeeau

Fixes could range from redirecting the endpoint, recompliation, rebuilding etc.

Please.
