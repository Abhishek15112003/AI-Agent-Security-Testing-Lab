from pypdf import PdfReader


def extract_pdf_text(
    filepath
):

    try:

        reader = PdfReader(
            filepath
        )

        content = []

        for page in (
            reader.pages
        ):

            text = (
                page.extract_text()
            )

            if text:

                content.append(
                    text
                )

        return "\n".join(
            content
        )

    except Exception as error:

        return (
            f"PDF_READ_ERROR: "
            f"{error}"
        )