# Improving Generalization of ML-based IDS with Lifecycle-based Dataset, Auto-Learning Features, and Deep Learning

This Github repository contains the code used in our paper.

## Abstract

During the past 10 years, researchers have extensively explored the use of machine learning (ML) in enhancing network intrusion detection systems (IDS). While many studies focused on improving accuracy of ML-based IDS, true effectiveness lies in robust generalization: the ability to classify unseen data accurately. Many existing models train and test on the same dataset, failing to represent the real unseen scenarios. Others who train and test using different datasets often struggle to generalize effectively. This study emphasizes the improvement of generalization through a novel composite approach involving the use of a lifecycle-based dataset (characterizing the attack as sequences of techniques), automatic feature learning (auto-learning), and a CNN-based deep learning model. The established model is tested on five public datasets to assess its generalization performance. The proposed approach demonstrates outstanding generalization performance, achieving an average F1 score of 0.85 and a recall of 0.94. This significantly outperforms the 0.56 and 0.42 averages recall achieved by attack-based datasets using CIC-IDS-2017 and CIC-IDS-2018 as training data, respectively. Furthermore, auto-learning features boost the F1 score by 0.2 compared to traditional statistical features. Overall, the efforts have resulted in significant advancements in model generalization, offering a more robust strategy for addressing intrusion detection challenges.

## Code

- `1_split_benign_attack_pcap`: This script splits the raw pcap data into benign and attack categories. This is necessary for some datasets where the traffic is mixed within a single pcap file. The script uses the ground truth of the dataset, including timestamps and IP addresses of attackers and targets, for the splitting process.

- `2_pcap_to_feather`: This script extracts pcap files into a dataset format (we use `.feather`) for both auto learning and statistical feature extraction.

- `3_training_models_and_inter_testing_data`: Contains the code for training models with auto learning and statistical features. It also includes methods for conducting generalization tests using the inter testing dataset approach.

- `CNN_model`: Contains the saved CNN model for all scenarios involving auto learning features.

## Citation

If you utilize our code or findings in your research, please cite our paper as follows:
---
@ARTICLE{generalization,
author={Sudyana, Didik and Verkerken, Miel and Lin, Ying-Dar and Hwang, Ren-Hung and Lai, Yuan-Cheng and D’hooge, Laurens and Wauters, Tim and Volckaert, Bruno and De Turck, Filip},
journal={IEEE Transactions on Machine Learning in Communications and Networking},
title={Improving Generalization of ML-based IDS with Lifecycle-based Dataset, Auto-Learning Features, and Deep Learning},
year={2024},
volume={in revision}
}
---
