from ml.forecaster import MarkovThreatForecaster

def train():
    print("Fitting Markov Threat Forecaster transition matrix...")
    sample_sequences = [
        ["BENIGN", "DGA", "DNS_TUNNEL", "C2_BEACON"],
        ["BENIGN", "DNS_TUNNEL", "C2_BEACON", "SYN_FLOOD"],
        ["BENIGN", "SLOWLORIS", "UDP_FLOOD"],
        ["DGA", "DNS_TUNNEL", "C2_BEACON"],
        ["DNS_TUNNEL", "C2_BEACON", "UDP_FLOOD"]
    ]
    forecaster = MarkovThreatForecaster()
    forecaster.train_from_sequences(sample_sequences)
    print("Markov Forecaster fitted successfully.")

if __name__ == "__main__":
    train()
