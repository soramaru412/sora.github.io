---
title: "HTB CDSA — My Certification Journey"
published: 2026-07-05
description: "My honest experience taking the Certified Defensive Security Analyst exam from Hack The Box."
image: ''
tags: [HTB, CDSA, Blue Team, SOC, Certification]
category: Reviews
draft: false
---

It's been a long time since I got my CDSA. But I wanted to share a bit about my exam journey — partly to look back and see how far I've come, and partly to help those of you out there who are still on the fence about whether to take CDSA, and what you'll need to prepare.

![HTB CDSA certificate](./Page1.png)

---

## Why I Chose CDSA

I picked CDSA because it felt harder and more practical than BTL1 or SAL1. At the time, I wanted to move my career from GRC and Data Privacy into SOC and Blue Team work, so I needed something hands-on that would actually build the skills I was missing.

---

## Preparation

To sit the CDSA exam, you first have to complete HTB's SOC Analyst path — it's a prerequisite. So that's where I started.

At first I also planned to buy extra labs like [CyberDefenders](https://cyberdefenders.org/) and [LetsDefend](https://letsdefend.io/) to practice more and get comfortable with SIEM tools. But I ran out of time, so that never happened.

:::caution[Don't do what I did]
I made a bold (read: reckless) decision — I quit my job to focus on studying. 😅 To be fair, I was already planning to leave that role since it didn't fit the direction I wanted to go. I just needed time to grind the cert, so I left a bit earlier than planned.
:::

I started the SOC Analyst path feeling relaxed and excited. I even went back over topics I already knew, just to refresh. But as time went on — and with Lunar New Year (Tết) landing right in the middle — I got lazier and stopped studying as much as I'd planned.

After the holiday, I had to scramble. I skipped quickly through the parts I already knew and focused only on what mattered most for the exam: SIEM, log analysis, and digital forensics.

---

## The Exam

I started my exam at 9 PM on March 10th.

There are **two incidents**:

- **Incident 1** — a CTF-style section with 20 flags to submit
- **Incident 2** — a free-form written investigation

Incident 2 caught me off guard. I hadn't expected a written format, and at first I had no idea how to approach it. So I decided to tackle Incident 1 first.

### Incident 1

I got stuck right on the very first question. Almost three hours in, and I still hadn't solved a single flag. I started to panic. 🥲

Before going to bed, I forced myself to sit with it a little longer — and luckily, things finally clicked.
After solving the first question, I rode that momentum and cleared a few more. Some questions come in bundles — once you figure out the first one, the later ones build on the same clues, so they get easier.

At the start, my mindset was just "passing is enough." In the end, I solved 19 out of 20 flags. There was one I could never crack, and honestly, that still bugs me.

### Incident 2

I went into this one like a blank sheet of paper. Since it wasn't CTF-style, I wasn't sure what exactly I needed to follow. It was completely freestyle.

Luckily, I found an article about the type of attack used in Incident 2. That let me start thinking like an attacker, which made tracing everything much easier. The picture got clearer and clearer as I went.

---

## Tips That Helped Me

:::tip[Think like an attacker]
Map out the kill chain. How would the attack unfold? What tools might they use? Then match that thinking to the right event or process IDs to follow the trail.
:::

:::warning[Watch out for noise]
The exam environment is built for testing, so there will be noise in the logs. Stay sharp and don't fall down a rabbit hole.
:::

:::important[Screenshot everything as you go]
I thought I'd have plenty of time — I finished both incidents in about 4 days. But writing the analysis report ended up taking the longest. You need to gather enough evidence, so take full screenshots with short notes *while* you're solving. Otherwise you'll have to redo your work just to get the screenshots, which is painful.
:::

You can use a tool like **Sysreptor** to generate the report in HTB's format. I was too much of a beginner for that, so I just filled in the template HTB provided. Next time I take an HTB cert, I'll give Sysreptor a try.

---

## The Wait

I submitted my work and then waited, nervously. I'd heard grading can take up to 20 days.

I lost sleep over it, imagining every scenario where I failed — I even dreamed about it. There's a retake available, so I stayed somewhat confident. But honestly, if I had to redo it, I really didn't want to. 🙃

Three days after submitting, while I was asleep, the result email arrived. I opened it with shaky hands and — yay!

![HTB certified](./unnamed.gif)

<h1 style="color: #9fef00; text-align: center; font-size: 2.5rem;">You're a certified hacker!</h1>

---

## Should You Take It?

I highly recommend this cert. It's a solid, hands-on certification for anyone working in — or wanting to move into — SOC Analyst, Blue Team, or Forensics roles.

The price is reasonable, the quality is worth it, and the exam design is well thought out. It doesn't just test your investigation skills — it also pushes you to practice writing a proper report, which is a skill that actually matters on the job.
