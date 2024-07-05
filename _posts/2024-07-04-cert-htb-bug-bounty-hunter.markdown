---
title: "HackTheBox Certified Bug Bounty Hunter Review"
date:  2024-07-04 00:03:00 +0500
header:
  teaser: "/assets/images/18/image_2024-07-04_14-56-48.png"
categories: 
  - exam
tags:
  - redteam
  - bugbounty
  - hackthebox
  - review
  - hacking
---

*The HTB Certified Bug Bounty Hunter* is a hands-on certification that evaluates candidates' skills in bug hunting and web application testing.     

HTB Certified Bug Bounty Hunter holders will have intermediate level technical competency in the areas of bug hunting and web application penetration testing.    

![htb](/assets/images/18/image_2024-07-04_17-56-22.png){:class="img-responsive"}      

Hi all!

### whoami

**ha1s3nb3rgg** - pentester, bug hunter, cybersecurity researcher, SPACE and MG.RT CTF teams member.     

In this article I want to share with you a review of the `HTB CBBH` course and my experience of passing the exam.     

Before starting, I would like to answer the questions that I asked myself before starting the course:    


**1) Do you need any knowledge of the web to take this course?**     
You need a basic understanding of what web vulnerabilities are and how to use the tools.   
Although the course material is written clearly and understandably. You just need to carefully read the material and understand the essence of the vulnerability and bypassing the protections, since payloads on laboratory machines, the data in the module in particular, will not work on the wheelbarrow. This is where the HTB slogan comes into play - *"Think outside the box"* I had problems with this, but more on that later.    

**2) How long will it take to complete the course?**     
Everything is individual. You can complete the course in 1.5 months while sitting in the village, or you can spend six to a year completing it.     

![htb](/assets/images/18/image_2024-07-04_14-55-07.png){:class="img-responsive"}      

### Course overview

The course covers many topics related to web application security, from collecting information to exploiting vulnerabilities and writing business reports. The material is written clearly and clearly, after reading there is no need to additionally google and search for information.      

I would like to highlight the most interesting modules in my opinion:     

*Command Injections*     

Command injection vulnerabilities can be used to compromise a hosting server and its entire network. In this module, you will learn how to identify and exploit command injection vulnerabilities and how to use various filter bypass techniques to avoid compromised security.      

*File Upload Attacks*    

Arbitrary file downloading is one of the most serious vulnerabilities on the Internet. These vulnerabilities allow attackers to upload malicious files, execute arbitrary commands on the back-end server, and even gain control of the entire server and all web applications hosted on it and potentially access sensitive data or cause service failures.     

*Broken Authentication*     

Authentication is probably the simplest and most common measure used to ensure secure access to resources, and it is the first line of defense against unauthorized access. Authentication failure ranked No. 7 on OWASP's 2021 Top 10 Web Application Security Threats, which falls under the broader category of identity and authentication failures. A vulnerability or misconfiguration during the authentication phase can impact the overall security of the application.    

*File Inclusion*     

File inclusion is a common web application vulnerability that can easily be overlooked as part of a web application's functionality.    

*Web Service & API Attacks*     

Web services and APIs are often used to provide certain functionality programmatically between heterogeneous devices and software components. Both web services and APIs can help integrate different applications or facilitate separation within a given application. This module covers how to define the functionality of a web service or API and exploit any security flaws.     

At the time of starting the course, I am a hungry student who chooses between going to the village and taking the course and trying to pass the exam, or staying in Almaty and working as a waiter/hookah man:     

![htb](/assets/images/18/almaty.jpg){:class="img-responsive"}      
*Photo credit: Maxim Zolotukhin.*     

I chose the first option and had the opportunity to do an internship at `MSSP.GLOBAL` online, where at first I interned in the field of malware development with [@cocomelonc](https://cocomelonc.github.io/), but later I moved to [Saken Tleuberdin](https://www.linkedin.com/in/st0301/) in web pentesting and was able to apply the acquired skills on HTB on real cases.     

Speaking of course speed and *"think outside the box"* - I spent a lot of time on some lab machines because I couldn't adopt the *"think outside the box"* mindset. But as soon as I did this, life became much easier and more enjoyable.      

### Exam structure
The exam covers 5 vulnerable web services; on each of them you need to capture the site administrator and get an RCE.     

1 web service == 2 flags with different scores.     

To pass the exam, you need to get 80/100 points and write a commercial report, which outlines each step of the student. Otherwise, your report will be returned to you for revision and you will have to wait another 20 business days :) The report must indicate the vulnerability, describe in detail your steps, as well as the CVSS assessment.     

### Exam experience

*I passed the exam on the second try.*      
On my first attempt at the exam, I spent a very long time on the rabbit hole. I can't reveal the details of the exam, but if I told you what I got stuck on and how stupid it was, you would laugh heartily XD. Having discovered a couple more vulnerabilities, I wrote a report and submitted it.
After `2 weeks`, feedback came from `HTB`. I set a date for the exam and started preparing.     

*Second try*    
Having solved all the laboratory machines of the course and switched to Portswigger, I began my 2nd attempt.    

One of the attack vectors was not demonstrated in the course, which is why I was stuck on it for 6 days and only after 6 days I was able to exploit it.      

Perhaps the vector was listed in links to other articles in the module and I didn’t see it. As my friend said, *"Google is in your hands."*     

Solving machines on Portswigger helped me get things moving in the exam when I decided to look at my `BSCP` records for one of the web services.     

Having collected 8 flags out of 10 and scoring 85 points out of 100 - I completed the exam and submitted the report!      

![htb](/assets/images/18/photo_2024-06-07_03-14-04.jpg){:class="img-responsive"}      

After the longest month of waiting, the treasured letter from HackTheBox **"You are certified hacker"** arrived. Which I was very happy about, since this was my first certification:     

![htb](/assets/images/18/photo_2024-06-21_21-31-41.jpg){:class="img-responsive"}      

### Summary

To summarize this course and exam:    
- The course and material in the course are quite good and understandable. `10/10`      
- The exam is interesting but with pitfalls XD. `10/10`     

![htb](/assets/images/18/image_2024-07-04_14-56-48.png){:class="img-responsive"}      

> P.S. In parallel with passing the exam from HTB, I took exams from the university and had to set priorities.... That's why I ended up in the summer semester at the university XD.

Good luck to everyone and think outside the box!!!

By MG.RT team member from MSSP Research Lab:      

- [@ha1s3nb3rgg](https://x.com/walterw95385335)     

### References

[My Telegram Channel](https://t.me/ha1s3nlights)      
[Github](https://github.com/ha1s3nb3rgg)     
[Introducing Hack The Box Academy Certifications](https://www.hackthebox.com/blog/hack-the-box-academy-certifications)     

Thanks for your time happy hacking and good bye!         
*All drawings and screenshots are MSSPLab's*       
