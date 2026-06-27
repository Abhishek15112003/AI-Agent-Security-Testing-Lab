import xml.etree.ElementTree as ET


def extract_xml_text(filepath):

    try:

        tree = ET.parse(filepath)

        root = tree.getroot()

        content = []

        for element in root.iter():

            if element.text:

                content.append(
                    element.text
                )

        return "\n".join(content)

    except Exception as error:

        return (
            f"XML_READ_ERROR: "
            f"{error}"
        )