# 🛠️ MS Office - Custom XML parts

## Theory

[**XML Custom Parts** ](https://learn.microsoft.com/en-us/visualstudio/vsto/custom-xml-parts-overview?view=vs-2022)are structured data containers embedded within Microsoft Office documents (like DOCX, XLSX, or PPTX). Unlike visible content (text, charts, etc.), these parts are stored separately from the main document body and are primarily used by developers to hold configuration data, metadata, or information consumed by Office add-ins.

Each custom part is represented as a separate `.xml` file inside the Office document archive (which is a ZIP file under the hood), and they are typically stored in the `/customXml/` directory. These XMLs can include arbitrary data—Office doesn’t validate their content unless explicitly linked with active components like macros or embedded scripts.

From a red team perspective, XML Custom Parts offer a stealthy location to hide payloads, shellcode, or indicators used later during exploitation. Since they don’t directly impact document rendering or functionality, they may escape attention during casual inspection or static analysis.

## Practice

{% tabs %}
{% tab title="Manually" %}
//TO DO
{% endtab %}

{% tab title="Automated" %}
//TO DO
{% endtab %}
{% endtabs %}

## Poc

// TO DO

## Resources

{% embed url="https://mgeeky.tech/payload-crumbs-in-custom-parts/" %}
