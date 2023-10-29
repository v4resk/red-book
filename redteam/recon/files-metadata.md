# Files Metadata

## Theory

To identify potential target users and gather information about their operating systems and installed application software, we might review the metadata of publicly accessible documents linked to the target organization.

## Practice

{% tabs %}
{% tab title="Exiftool" %}
We may find and download target organization's publicly accessible documents by using [google dorks](google-dorks.md) such as `site:example.com filetype:pdf` or by directly downloading files from the organization's website.

Then, exfitool can be used to inspect metadata tags

```bash
# -u : Display unknown tags
# -a : Display duplicated tags
exiftool -u -a corpo-image.png
```
{% endtab %}
{% endtabs %}
