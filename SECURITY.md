# Vulnerability Disclosure and Embargo Policy

The Enarx project welcomes the responsible disclosure of vulnerabilities, including those discovered in:
- Enarx code
- Enarx dependencies (even compilers)
- Enarx documentation
- 3rd party hardware or firmware

## Initial Contact

All security bugs in Enarx should be reported to the security team. 
To do so, please reach out either by email at security@enarx.dev or on the
[Enarx Chat](https://chat.enarx.dev) stating you'd like to report a security
issue, but **without divulging details**.

From then, we will establish a more secure area where the issue can be
discussed, in the form of a 
[Github Security Advisory](https://help.github.com/en/github/managing-security-vulnerabilities/about-github-security-advisories).

You will be invited to join this private area to discuss specifics. Doing so 
allows us to start with a high level of confidentiality and relax it if the 
issue is less critical, moving to work on the fix in the open.

Your initial contact will be acknowledged within 48 hours, and you’ll receive 
a more detailed response within 96 hours indicating the next steps in handling 
your report.

After the initial reply to your report, the security team  will endeavor to 
keep you informed of the progress being made towards a fix and full 
announcement. As recommended by 
[RFPolicy](https://dl.packetstormsecurity.net/papers/general/rfpolicy-2.0.txt),
 these updates will be sent at least every five working days.

If you have not received a reply to your initial contact within 96 hours, or
have not heard from the security team for the past five days, there are a few
steps you can take (in suggested order):
- Contact the current security coordinator ([Nathaniel McCallum](https://github.com/npmccallum)) directly
- Contact the back-up contact ([Mike Bursell](https://github.com/mikecamel)) directly  
- Contact the team as a whole on the [Enarx Chat](https://chat.enarx.dev).

As a reminder, **when escalating in these venues, please do not discuss your
issue.** 


## Disclosure Policy

The Enarx project has a 5 step disclosure process.
1. Contact is established, a private channel created, and the security report 
is received and is assigned a primary handler. This person will coordinate the fix and release process.
2. The problem is confirmed and a list of all affected versions is determined. If an embargo is needed (see below), details of the embargo are decided.
3. Code is audited to find any potential similar problems.
4. Fixes are prepared for all releases which are still under maintenance. In case of embargo, these fixes are not committed to the public repository but rather held in a private fork pending the announcement.
5. The changes are pushed to the public repository and new builds are deployed.
  An announcement is sent to Enarx public channels (chat, website), once
  these are available.

This process can take some time, especially when coordination is required 
with maintainers of other projects or, for instance, with hardware vendors. 
Every effort will be made to handle the bug in as timely a manner as possible, 
however it is important that we follow the release process above to ensure 
that the disclosure is handled in a consistent manner.

Enarx does not provide financial rewards for security disclosures, but the 
team is open to working with reporters of issues on publishing and attribution 
of vulnerabilities and fixes. We welcome reports of issues to the project, 
and want to ensure that the community is aware of and celebrates security 
improvements.

## Embargoes

While the Enarx project aims to follow the highest standards of transparency 
and openness (cf. [Enarx Principles](https://github.com/enarx/enarx/wiki/Design-principles)), 
handling some security issues may pose such an immediate threat to various 
stakeholders and require coordination between various actors that it cannot 
be made immediately public.

In this case, security issues will fall under an embargo.

An embargo can be called for in various cases:
- when disclosing the issue without simultaneously providing a mitigation 
  would seriously endanger users,
- when producing a fix requires coordinating between multiple actors (such as
   upstream or downstream/dependency projects), or simply
- when proper analysis of the issue and its ramifications demands time.

If we determine that an issue you report requires an embargo, we will discuss 
this with you and try to find a reasonable expiry date (aka “embargo 
completion date”), as well as who should be included in the list of 
need-to-know people.


---

## Reference

Please refer to this [RFC](https://github.com/enarx/rfcs/tree/master/00002-vulnerability-disclosure-and-embargo-policy) for background.
