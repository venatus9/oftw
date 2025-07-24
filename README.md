# OFTW LLM workflow test
This repository is a result of the experience gained from the **'Objective For The We v3' - "how to use LLMs to detect macOS malware"** training.

Here is demonstrated an automated workflow of *logging data -> pre-processing that data -> analysing this data with an LLM* in order to detect malware (particularly for macOS).

The files held in the ```data*``` folders are placeholders, the scripts should generate their own files given the chance to run locally on macOS (although this hasn't been tested thoroughly).
Due to the fact that github likely doesn't run workflows on macOS, the ```fetch_data.py``` file doesn't change the placeholder file in ```data/data.json```, hence the output in ```results.csv``` recording macOS data, when theoretically it shouldn't.
