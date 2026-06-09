from io import BytesIO

import pandas as pd


def load_uploaded_frame(
    compressed_csv: bytes,
) -> pd.DataFrame:
    return pd.read_csv(
        BytesIO(
            compressed_csv
        ),
        compression="gzip",
    )
