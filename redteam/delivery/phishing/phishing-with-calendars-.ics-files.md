# Phishing with Calendars (.ICS Files)

## Theory

We can leverage calendar invites as an initial access vector, using the [_iCalendar_](https://docs.fileformat.com/email/ics/) (ICS) file format to create a phishing scenario.

The ICS File format is used on several Calendars like Google Calendar, Outlook, and Apple Calendar.

## Practice

#### .ICS Format File Overview

The easiest way to get a .ics file is by creating a Google Calendar invite from one Gmail account to another and then downloading the **invite.ics** email attachment.&#x20;

An example of an Exchange .ICS file can be found below:

<details>

<summary>.ICS Example</summary>

<pre><code>BEGIN:VCALENDAR
PRODID:Microsoft Exchange Server 2022
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VTIMEZONE
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
TZNAME:GMT+2
BEGIN:STANDARD
DTSTART:19701025T030000
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
<strong>DTSTART;TZID=Europe/Paris:20241224T080000
</strong><strong>DTEND;TZID=Europe/Paris:20241224T090000
</strong>DTSTAMP:20241012T034159Z
<strong>ORGANIZER;CN=Henry:mailto:henry24@infiltr8.io
</strong>UID:1fmijtln7pfe0ccot1n4skuan4
CREATED:20241010T034159Z
<strong>DESCRIPTION:http://evil.com
</strong>LAST-MODIFIED:20241219T212644Z
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE;CN=v4resk;X-NUM-GUESTS=0:mailto:v4resk@gmail.com
LOCATION:Microsoft Teams Meeting
SEQUENCE:0
<strong>STATUS:CONFIRMED
</strong>SUMMARY:HR meeting
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
</code></pre>



</details>

Interesting fields can be found below

<table><thead><tr><th width="171">Fields</th><th>Comment</th></tr></thead><tbody><tr><td>UID</td><td>UID Should be uniq and regenerated each times</td></tr><tr><td>ORGANIZER</td><td>The organizer can be spoofed by modifying the <code>CN=</code> value</td></tr><tr><td>ATTENDEE</td><td>You can add as many attendee as you’d like</td></tr><tr><td>PARTSTAT</td><td>We can force Attendees To Accept The Invite by setting <code>PARTSTAT=ACCEPTED</code> </td></tr><tr><td>DTSTART / DTEND</td><td>This properties specify the start and end times of the event</td></tr><tr><td>DESCRIPTION</td><td>It provides additional details about the event, and can be used to insert malicious contents / links.</td></tr></tbody></table>

#### Phishing Attack

{% tabs %}
{% tab title="Malicious URL" %}
[Fakemeeting](https://github.com/ExAndroidDev/fakemeeting) can be used to automate the process of creating `.ICS` phishing files. These invites can include a phishing URL, inside the DESCRIPTION field, crafted with a convincing pretext, encouraging the target to download a file or enter their credentials.

```bash
# 1. Edit fakemeeting.py
# 2. execute
python fakemeeting.py
```
{% endtab %}
{% endtabs %}

## Resources

{% embed url="https://appriver.com/resources/blog/june-2020/phishers-are-targeting-your-calendar-ics-files" %}

{% embed url="https://isc.sans.edu/diary/Spam+Delivered+via+ICS+Files/21611" %}

{% embed url="https://mrd0x.com/spoofing-calendar-invites-using-ics-files/" %}
