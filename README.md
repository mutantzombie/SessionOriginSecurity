Towards Defeating Cross-Site Request Forgery
=====================

Mike Shema <mike@deadliestwebattacks.com> [@CodexWebSecurum](https://twitter.com/CodexWebSecurum)

Adapted from the original post at [http://deadliestwebattacks.com/2013/08/08/and-they-have-a-plan/](). 

Some background on Cross-Site Request Forgery is at [http://deadliestwebattacks.com/2013/01/21/user-agent-secret-agent-double-agent/]().

Thanks to Vaagn Toukharian <[@tukharian](https://twitter.com/tukharian)> for input, feedback, and design help.

Contents
---

* [The Problem](#problem)
* [The Proposed Solution](#solution)
* [Format](#syntax)
* [Policies](#policies)
* [Benefits](#benefits)
* [Considerations](#considerations)
* [Notes](#notes)
* [Cautions](#cautions)
* [TODO](#todo)
* [Additional Resources & References](#references)

[The Problem](id:problem)
===
Cross-Site Request Forgery (CSRF) abuses the normal ability of browsers to make cross-origin requests by crafting a resource on one origin that causes a victim’s browser to make a request to another origin using the victim’s security context associated with that target origin.

The attacker creates and places a malicious resource on an origin unrelated to the target origin to which the victim’s browser will make a request. The malicious resource contains content that causes a browser to make a request to the target origin. That request contains parameters selected by the attacker to affect the victim’s security context with regard to the target origin.

The attacker does not need to violate the browser’s Same Origin Policy to generate the cross origin request. Nor does the attack require reading the response from the target origin. The victim’s browser automatically includes cookies associated with the target origin for which the forged request is being made. Thus, the attacker creates an action, the browser requests the action and the target web application performs the action under the context of the cookies it receives — the victim’s security context.

An effective CSRF attack means the request modifies the victim’s context with regard to the web application in a way that’s favorable to the attacker. For example, a CSRF attack may change the victim’s password for the web application.

CSRF takes advantage of web applications that fail to enforce strong authorization of actions during a user’s session. The attack relies on the normal, expected behavior of web browsers to make cross-origin requests from resources they load on unrelated origins.

The browser’s Same Origin Policy prevents a resource in one origin to read the response from an unrelated origin. However, the attack only depends on the forged request being submitted to the target web app under the victim’s security context — it does not depend on receiving or seeing the target app’s response.

[Proposed Solution: Session Origin Security](id:solution)
===

The SOS specification proposes additional directives for the Content Security Policy in order to counter CSRF attacks. Its behavior includes pre-flight requests as used by the Cross Origin Resource Sharing spec.

The name is intended to evoke the SOS of Morse code, which is both easy to transmit and easy to understand. The acronym may stand for "Session Origin Security", although "Save Our Site" would be just as appropriate. 

An SOS policy may be applied to one or more cookies for a web application on a per-cookie or collective basis. The policy controls whether the browser includes those cookies during cross-origin requests. (A cross-origin resource cannot access a cookie from another origin, but it may generate a request that causes the cookie to be included.)

Instances of Cross-Origin Requests
---

Any request generated from a resource whose browsing context or parent origin does not match the destination origin of the request is considered a cross-origin request.

[Format](id:format)
===

A web application sets a policy by including a Content-Security-Policy response header. This header may accompany the response that includes the Set-Cookie header for the cookie to be covered, or it may be set on a separate resource.

A policy for a single cookie would be set as follows, with the cookieName of the cookie and a directive of 'any', 'self', or 'isolate'. (Those directives will be defined shortly.)

Content-Security-Policy: sos-apply=cookieName 'policy'

A response may include multiple CSP headers, such as:

Content-Security-Policy: sos-apply=cookieOne 'policy'  
Content-Security-Policy: sos-apply=cookieTwo 'policy'

A policy may be applied to all cookies by using a wildcard:

Content-Security-Policy: sos-apply=* 'policy'

[Policies](id:policies)
===

One of three directives may be assigned to a policy. The directives affect the browser’s default handling of cookies for cross-origin requests to a cookie’s destination origin. The pre-flight concept will be described in the next section; it provides a mechanism for making exceptions to a policy on a per-resource basis.

Policies are only invoked for cross-origin requests. Same origin requests are unaffected.

'any' — include the cookie. This represents how browsers currently work. Make a pre-flight request to the resource on the destination origin to check for an exception response.

'self' — do not include the cookie. Make a pre-flight request to the resource on the destination origin to check for an exception response.

'isolate' — never include the cookie. Do not make a pre-flight request to the resource because no exceptions are allowed.

Some examples of a header:

Content-Security-Policy: sos-apply=sessionid 'isolate'  
Content-Security-Policy: sos-apply=sessionid 'self'  
Content-Security-Policy: sos-apply=lang 'any'

Pre-Flight
===

A browser that is going to make a cross-origin request that includes a cookie covered by a policy of 'any' or 'self' must make a pre-flight check to the destination resource before conducting the request. (A policy of 'isolate' instructs the browser to never include the cookie during a cross-origin request.)

The pre-flight request enables the destination origin to modify a policy on a per-resource basis. Thus, certain resources of a web app may allow or deny cookies from cross-origin requests despite the default policy.

The pre-flight request works identically to that for Cross Origin Resource Sharing, with the addition of an Access-Control-SOS header. This header includes a space-delimited list of cookies that the browser might otherwise include for a cross-origin request, as follows:

Access-Control-SOS: cookieOne CookieTwo

A pre-flight request might look like the following, note that the Origin header is expected to be present as well:

OPTIONS https://web.site/resource HTTP/1.1  
Host: web.site  
Origin: http://other.origin  
Access-Control-SOS: sid  
Connection: keep-alive  
Content-Length: 0  

The destination origin may respond with an Access-Control-SOS-Reply header that instructs the browser whether to include the cookie(s). The response will either be 'allow' or 'deny'.

The response header may also include an expiration in seconds. The expiration allows the browser to remember this response and forego subsequent pre-flight checks for the duration of the value.

The following example instructs the browser to include a cookie with a cross-origin request to the destination origin even if the cookie’s policy had been 'self‘. (In the absence of a reply header, the browser would otherwise exclude the cookie.)

Access-Control-SOS-Reply: 'allow' expires=600

The following example instructs the browser to exclude a cookie with a cross-origin request to the destination origin even if the cookie’s policy had been 'any'. (In the absence of a reply header, the browser would otherwise include the cookie.)

Access-Control-SOS-Reply: 'deny' expires=0

The browser would be expected to track policies and policy exceptions based on destination origins. It would not be expected to track pairs of origins (e.g. different cross-origins to the destination) since such a mapping could easily become cumbersome, inefficient, and more prone to abuse or mistakes.

As described in this section, the pre-flight is an all-or-nothing affair. If multiple cookies are listed in the Access-Control-SOS header, then the response applies to all of them. This might not provide enough flexibility. On the other hand, simplicity tends to encourage security.

[Benefits](id:benefits)
===

A policy can be applied on a per-cookie basis. If a policy-covered cookie is disallowed, any non-covered cookies for the destination origin may still be included. Think of a non-covered cookie as an unadorned or “naked” cookie — their behavior and that of the browser matches the web of today.

The intention of a policy is to control cookies associated with a user’s security context for the destination origin. For example, it would be a good idea to apply 'self' or 'isolate' to a cookie used for authorization (and identification, depending on how tightly coupled the app treats those concepts with regard to the cookie).

Imagine a WordPress installation hosted at https://web.site/. The site’s owner wishes to allow anyone to visit, especially when linked-in from search engines, social media, and other sites of different origins. In this case, they may define a policy of 'any' set by the landing page:

Content-Security-Policy: sos-apply=sid 'any'

However, the /wp-admin/ directory represents sensitive functions that should only be accessed by intention of the user. WordPress provides a robust nonce-based anti-CSRF token. Unfortunately, many plugins forget to include these nonces and therefore become vulnerable to attack. Since the site owner has set a policy for the sid cookie (which represents the session ID), they could respond to any pre-flight request to the /wp-admin/ directory as follows:

Access-Control-SOS-Reply: 'deny' expires=86400

Thus, the /wp-admin/ directory would be protected from CSRF exploits because a browser would not include the sid cookie with a forged request.

The use case for the 'isolate' policy is straight-forward: the site does not expect any cross-origin requests to include cookies related to authentication or authorization. A bank or web-based email might desire this behavior. The intention of isolate is to avoid the need for a pre-flight request and to forbid exceptions to the policy.


[Considerations](id:considerations)
===
Policy via CSP header or Cookie annotation
---

A CSP header was chosen in favor of decorating the cookie with new attributes because cookies are already ugly, clunky, and (somewhat) broken enough. Plus, the underlying goal is to protect a session or security context associated with a user. As such, there might be reason to extended this concept to the instantiation of Web Storage objects, e.g. forbid them in mixed-origin resources. However, this hasn’t really been thought through and probably adds more complexity without solving an actual problem.


[Notes](id:notes)
===

The following thoughts represent some areas that require more consideration or that convey some of the motivations behind this proposal.

This is intended to affect cross-origin requests made by a browser.

It is not intended to counter same-origin attacks such as HTML injection (XSS) or intermediation attacks such as sniffing. Attempting to solve multiple problems with this policy leads to folly.

CSRF evokes two sense of the word “forgery”: creation and counterfeiting. This approach doesn’t inhibit the creation of cross-origin requests (whereas the “non-simple” XHR requests under CORS would). Nor does it inhibit the counterfeiting of requests, such as making it difficult for an attacker to guess values. It defeats CSRF by blocking a cookie that represents the user’s security context from being included in a cross-origin request that attempts to abuse the user's relation to the destination web app.

There may be a reason to remove a policy from a cookie, in which case a CSP header could use something like an sos-remove instruction:

Content-Security-Policy: sos-remove=cookieName

Cryptographic constructs are avoided on purpose. Even if designed well, they are prone to implementation error. They must also be tracked and verified by the app, which exposes more chances for error and induces more overhead. Relying on nonces increases the difficulty of forging (as in counterfeiting) requests, whereas this proposed policy defines a clear binary of inclusion/exclusion for a cookie. A cookie will or will not be included vs. a nonce might or might not be predicted.

PRNG values are avoided on purpose, for the same reasons as cryptographic nonces. It’s worth noting that misunderstanding the difference between a random value and a cryptographically secure PRNG (which a CSRF token should favor) is another point against a PRNG-based control.

The pre-flight request/response shouldn’t be a source of information leakage about cookies used by the app. At least, it shouldn’t provide more information than might be trivially obtained through other techniques.

It’s not clear what an ideal design pattern would be for deploying SOS headers. A policy could accompany each Set-Cookie header. Or the site could use a redirect or similar bottleneck to set policies from a single resource.

It would be much easier to retrofit these headers on a legacy app by using a Web App Firewall than it would be trying to modify code to include nonces everywhere.

It would be (possibly) easier to audit a site’s protection based on implementing the headers via mod_rewrite tricks or WAF rules that apply to whole groups of resources than it would for a code audit of each form and action.

[Cautions](id:cautions)
===

In addition to the previous notes, these are highlighted as particular concerns.

**Conflicting Policies**  
Conflicting policies would cause confusion. For example, two different resources separately define an 'any' and 'self' for the same cookie. It would be necessary to determine which receives priority.

**Same Origin and Sub Origin**  
Cookies have the unfortunate property that they can belong to multiple origins (i.e. sub-domains). Hence, some apps might incur additional overhead of pre-flight requests or complexity in trying to distinguish cross-origin of unrelated domains and cross-origin of sub-domains.

**The "Return URL" Problem**  
Apps that rely on “Return To” URL parameters might not be fixed if the return URL has the CSRF exploit and the browser is now redirecting from the same origin. This needs some investigation.

This would be a scenario where SOS can't provide adequate protection, but it wouldn't be a strong reason to dismiss it -- even CSP has 'unsafe-inline' to accommodate apps that can't separate JavaScript resources adequately.

In this case, the security burden shifts back to the developer to review to Return URL mechanism. For example, the app could verify Origin request headers or restrict actions permitted via the Return URL.

**Only Protects the Protected**  
There’s no migration for old browsers: You’re secure (using a supporting browser and an adopted site) or you’re not. On the other hand, an old browser is an insecure browser anyway -- browser exploits are more threatening than CSRF for many, many cases.

An apt comparison might be the X-FRAME-OPTIONS header. Sites may set this header to defeat framing-based attacks such as clickjacking, but only within User Agents that correctly handle the header. Otherwise, the site must rely on JavaScript-based anti-framing code to protect legacy UAs. (This [paper](http://seclab.stanford.edu/websec/framebusting/framebust.pdf) describes the clickjacking problem in detail.)

[TODO](id:todo)
===
Could this be used to create more granularity within same origin resources? (Look at Navigation Controller for references)

How would this handle data: schemes? What Origin do browsers consider them to be? What would an attack look like like leveraged that as an attack vector?

Demonstrate how this could be implemented by Web App Firewall rules.

[Additional Resources & References](id:references)
===
* Content Security Policy. [http://www.w3.org/TR/CSP/]()
* Cross-Origin Resource Sharing. [http://www.w3.org/TR/cors/]()
* "Lightweight Server Support for Browser-Based CSRF Protection". [http://research.microsoft.com/en-us/um/people/helenw/papers/racl.pdf]()
* "Robust Defenses for Cross-Site Request Forgery". [http://www.adambarth.com/papers/2008/barth-jackson-mitchell-b.pdf]()
* SameDomain cookies. [https://github.com/mozmark/SameDomain-cookies]()

Later work
----
- First-Party Cookies [Draft RFC](https://tools.ietf.org/html/draft-west-first-party-cookies-07).
   - This is notable for being implemented in the Google Chrome Browser. Check out the [commit](https://codereview.chromium.org/1783813002).
   - It was referenced in the BlackHat Asia 2016 [briefing](https://www.blackhat.com/docs/asia-16/materials/asia-16-Karakostas-Practical-New-Developments-In-The-BREACH-Attack.pdf) (slide 35) by Dimitris Karakostas and Dionysis Zindros that called out the benefits of anti-CSRF measures vs. TLS [BREACH-style](http://breachattack.com) vulnerabilities.

