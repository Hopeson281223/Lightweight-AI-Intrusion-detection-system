def test_ml_prediction():
    """Test direct ML prediction endpoint with correct features"""
    print("\n🤖 ML PREDICTION ENDPOINT TEST")
    try:
        # Get the actual feature names from your system
        from app.ml.preprocess import LIVE_FEATURES
        print(f"   📋 Expected features: {len(LIVE_FEATURES)}")
        
        # Create properly sized sample features
        sample_features = [0.0] * len(LIVE_FEATURES)
        
        # Set some realistic values for key features
        if len(sample_features) > 0: sample_features[0] = 443   # Destination Port
        if len(sample_features) > 1: sample_features[1] = 5.0   # Flow Duration  
        if len(sample_features) > 2: sample_features[2] = 10    # Total Fwd Packets
        if len(sample_features) > 3: sample_features[3] = 8     # Total Backward Packets
        if len(sample_features) > 4: sample_features[4] = 1500  # Total Length of Fwd Packets
        if len(sample_features) > 5: sample_features[5] = 1200  # Total Length of Bwd Packets
        
        prediction_response = requests.post(
            'http://localhost:8000/predict',
            json={"dataset": "cic", "features": sample_features},
            timeout=10
        )
        
        if prediction_response.status_code == 200:
            result = prediction_response.json()
            print(f"   ✅ ML Prediction: {result['label']} (confidence: {result['confidence']:.2f})")
            return True
        else:
            print(f"   ❌ ML Prediction FAILED: {prediction_response.status_code}")
            print(f"   📝 Response: {prediction_response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ ML Prediction ERROR: {e}")
        return False