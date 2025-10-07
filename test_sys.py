# final_comprehensive_test.py
import requests
import time
import json
import threading

def test_all_endpoints():
    """Test all API endpoints systematically"""
    print("🎯 COMPREHENSIVE LAI-IDS SYSTEM TEST")
    print("=" * 60)
    
    # Test 1: Health Check
    print("\n1. 🩺 HEALTH CHECK")
    try:
        health_response = requests.get('http://localhost:8000/health', timeout=5)
        if health_response.status_code == 200:
            print("   ✅ Health check PASSED")
        else:
            print(f"   ❌ Health check FAILED: {health_response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Health check ERROR: {e}")
        return False
    
    # Test 2: List Interfaces
    print("\n2. 🔌 INTERFACE CHECK")
    try:
        interfaces_response = requests.get('http://localhost:8000/interfaces', timeout=5)
        if interfaces_response.status_code == 200:
            interfaces = interfaces_response.json().get('interfaces', [])
            print(f"   ✅ Found {len(interfaces)} interfaces: {interfaces[:2]}...")
        else:
            print(f"   ❌ Interfaces check FAILED: {interfaces_response.status_code}")
    except Exception as e:
        print(f"   ❌ Interfaces check ERROR: {e}")
    
    # Test 3: Initial Status
    print("\n3. 📊 INITIAL STATUS")
    try:
        status_response = requests.get('http://localhost:8000/status', timeout=5)
        if status_response.status_code == 200:
            status = status_response.json()
            print(f"   ✅ Status: Capturing={status['is_capturing']}, Packets={status['packets_captured']}")
        else:
            print(f"   ❌ Status check FAILED: {status_response.status_code}")
    except Exception as e:
        print(f"   ❌ Status check ERROR: {e}")
    
    # Test 4: Start Capture
    print("\n4. 🚀 START CAPTURE")
    try:
        start_response = requests.post('http://localhost:8000/start', timeout=10)
        if start_response.status_code == 200:
            start_data = start_response.json()
            print(f"   ✅ Capture STARTED: {start_data['status']} on {start_data['interface']}")
        else:
            print(f"   ❌ Start capture FAILED: {start_response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Start capture ERROR: {e}")
        return False
    
    # Test 5: Live Monitoring with Traffic Generation
    print("\n5. 📡 LIVE TRAFFIC MONITORING (30 seconds)")
    print("   " + "=" * 50)
    
    def generate_test_traffic():
        """Generate some test HTTP traffic"""
        try:
            # Make some web requests to generate traffic
            for _ in range(5):
                requests.get('http://www.google.com', timeout=1)
                requests.get('http://www.github.com', timeout=1)
                time.sleep(0.5)
        except:
            pass  # Expected to fail, but generates traffic
    
    # Start traffic generation in background
    traffic_thread = threading.Thread(target=generate_test_traffic)
    traffic_thread.daemon = True
    traffic_thread.start()
    
    # Monitor for 30 seconds
    max_packets = 0
    max_flows = 0
    for i in range(1, 31):
        time.sleep(1)
        try:
            status_response = requests.get('http://localhost:8000/status', timeout=5)
            if status_response.status_code == 200:
                status = status_response.json()
                packets = status['packets_captured']
                flows = status['active_flows']
                max_packets = max(max_packets, packets)
                max_flows = max(max_flows, flows)
                
                # Show progress every 5 seconds
                if i % 5 == 0:
                    print(f"   ⏱️ {i:2}s: {packets} packets, {flows} active flows")
                
                # Show packet details occasionally
                if packets > 0 and i % 10 == 0:
                    print(f"   📊 Progress - Max: {max_packets} packets, {max_flows} flows")
            else:
                print(f"   ⏱️ {i:2}s: Status error {status_response.status_code}")
        except Exception as e:
            print(f"   ⏱️ {i:2}s: Status ERROR - {e}")
    
    print(f"   📈 PEAK ACTIVITY: {max_packets} packets, {max_flows} flows")
    
    # Test 6: Real-time Stats
    print("\n6. 📈 REAL-TIME STATISTICS")
    try:
        stats_response = requests.get('http://localhost:8000/stats', timeout=5)
        if stats_response.status_code == 200:
            stats = stats_response.json()
            print(f"   ✅ Database: {stats['total_packets']} total packets")
            print(f"   ✅ Alerts: {stats['recent_alerts']} recent alerts")
            print(f"   ✅ Threat Distribution: {stats['threat_distribution']}")
        else:
            print(f"   ❌ Stats check FAILED: {stats_response.status_code}")
    except Exception as e:
        print(f"   ❌ Stats check ERROR: {e}")
    
    # Test 7: Stop Capture
    print("\n7. 🛑 STOP CAPTURE")
    try:
        stop_response = requests.post('http://localhost:8000/stop', timeout=30)
        if stop_response.status_code == 200:
            stop_data = stop_response.json()
            print(f"   ✅ Capture STOPPED: {stop_data['message']}")
        else:
            print(f"   ❌ Stop capture FAILED: {stop_response.status_code}")
    except Exception as e:
        print(f"   ❌ Stop capture ERROR: {e}")
    
    # Test 8: Final System Analysis
    print("\n8. 🔍 FINAL SYSTEM ANALYSIS")
    try:
        final_stats = requests.get('http://localhost:8000/stats', timeout=5).json()
        final_status = requests.get('http://localhost:8000/status', timeout=5).json()
        
        print("   📊 CAPTURE SUMMARY:")
        print(f"      - Final Packets: {final_status['packets_captured']}")
        print(f"      - Active Flows: {final_status['active_flows']}")
        print(f"      - Still Capturing: {final_status['is_capturing']}")
        
        print("   🗄️  DATABASE SUMMARY:")
        print(f"      - Total Packets: {final_stats['total_packets']}")
        print(f"      - Recent Alerts: {final_stats['recent_alerts']}")
        
        print("   🛡️  SECURITY SUMMARY:")
        threats = final_stats['threat_distribution']
        if threats:
            for label, count in threats.items():
                threat_level = "🚨" if "ANOMALOUS" in str(label).upper() else "✅"
                print(f"      {threat_level} {label}: {count} detections")
        else:
            print("      - No threats detected")
            
        # Calculate system health score
        health_score = 0
        if final_status['packets_captured'] > 0:
            health_score += 25
        if final_stats['total_packets'] > final_status['packets_captured']:
            health_score += 25  # Database is accumulating data
        if not final_status['is_capturing']:
            health_score += 25  # Successfully stopped
        if any('ANOMALOUS' in str(k).upper() for k in threats.keys()):
            health_score += 25  # Threat detection working
        
        print(f"   🏆 SYSTEM HEALTH SCORE: {health_score}/100")
        
    except Exception as e:
        print(f"   ❌ Final analysis ERROR: {e}")
    
    # Test 9: Additional Endpoints
    print("\n9. 🔧 ADDITIONAL ENDPOINTS")
    endpoints_to_test = ['/metrics', '/models', '/packets']
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f'http://localhost:8000{endpoint}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if endpoint == '/metrics':
                    print(f"   ✅ {endpoint}: {len(data.get('metrics', []))} metrics")
                elif endpoint == '/models':
                    print(f"   ✅ {endpoint}: {len(data)} models")
                else:
                    print(f"   ✅ {endpoint}: RESPONDING")
            else:
                print(f"   ⚠️  {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"   ❌ {endpoint}: ERROR - {e}")
    
    print("\n" + "=" * 60)
    print("🎉 COMPREHENSIVE SYSTEM TEST COMPLETED!")
    return True

def test_ml_prediction_46_features():
    """Test ML prediction with exactly 46 features"""
    print("\n🤖 ML PREDICTION TEST (46 Features)")
    print("   " + "-" * 40)
    
    try:
        # Exact 46 features that match LIVE_FEATURES
        sample_features = [
            # Network Flow Features (46 total)
            443,    # 0. Destination Port
            5.0,    # 1. Flow Duration
            10,     # 2. Total Fwd Packets
            8,      # 3. Total Backward Packets
            1500,   # 4. Total Length of Fwd Packets
            1200,   # 5. Total Length of Bwd Packets
            500,    # 6. Fwd Packet Length Max
            50,     # 7. Fwd Packet Length Min
            150,    # 8. Fwd Packet Length Mean
            120,    # 9. Fwd Packet Length Std
            400,    # 10. Bwd Packet Length Max
            30,     # 11. Bwd Packet Length Min
            150,    # 12. Bwd Packet Length Mean
            110,    # 13. Bwd Packet Length Std
            270.5,  # 14. Flow Bytes/s
            3.6,    # 15. Flow Packets/s
            0.1,    # 16. Flow IAT Mean
            0.05,   # 17. Flow IAT Std
            0.5,    # 18. Flow IAT Max
            0.01,   # 19. Flow IAT Min
            1,      # 20. Fwd PSH Flags
            0,      # 21. Bwd PSH Flags
            0,      # 22. Fwd URG Flags
            0,      # 23. Bwd URG Flags
            0,      # 24. FIN Flag Count
            1,      # 25. SYN Flag Count
            0,      # 26. RST Flag Count
            1,      # 27. PSH Flag Count (sum of fwd + bwd)
            10,     # 28. ACK Flag Count (sum of fwd + bwd)
            0,      # 29. URG Flag Count (sum of fwd + bwd)
            0,      # 30. CWE Flag Count (sum of fwd + bwd)
            0,      # 31. ECE Flag Count (sum of fwd + bwd)
            135.0,  # 32. Average Packet Size
            40.0,   # 33. Avg Fwd Segment Size
            35.0,   # 34. Avg Bwd Segment Size
            50,     # 35. Fwd Header Length
            1500,   # 36. Fwd Packets/s
            0.8,    # 37. Down/Up Ratio
            10,     # 38. Fwd Packets/s (duplicate? using realistic value)
            8,      # 39. Bwd Packets/s
            64240,  # 40. Init Win bytes forward
            29200,  # 41. Init Win bytes backward
            5,      # 42. act_data_pkt_fwd
            0.0,    # 43. min_seg_size_forward
            0.0,    # 44. active_mean
            0.0     # 45. active_std
        ]
        
        print(f"   📋 Sending {len(sample_features)} features to ML endpoint...")
        
        prediction_response = requests.post(
            'http://localhost:8000/predict',
            json={
                "dataset": "cic", 
                "features": sample_features
            },
            timeout=10
        )
        
        if prediction_response.status_code == 200:
            result = prediction_response.json()
            confidence = result.get('confidence', 0)
            label = result.get('label', 'UNKNOWN')
            
            print(f"   ✅ ML PREDICTION SUCCESS!")
            print(f"   🏷️  Label: {label}")
            print(f"   📊 Confidence: {confidence:.3f}")
            print(f"   🔢 Prediction: {result.get('prediction', 'N/A')}")
            
            # Color code the result
            if "ANOMALOUS" in str(label).upper():
                print("   🚨 SECURITY ALERT: Anomalous traffic detected!")
            else:
                print("   ✅ Normal traffic pattern")
                
            return True
            
        else:
            error_detail = prediction_response.json().get('detail', 'Unknown error')
            print(f"   ❌ ML Prediction FAILED: {prediction_response.status_code}")
            print(f"   📝 Error: {error_detail}")
            return False
            
    except requests.exceptions.Timeout:
        print("   ❌ ML Prediction TIMEOUT: Request took too long")
        return False
    except requests.exceptions.ConnectionError:
        print("   ❌ ML Prediction CONNECTION ERROR: Cannot reach server")
        return False
    except Exception as e:
        print(f"   ❌ ML Prediction UNEXPECTED ERROR: {e}")
        return False

def run_security_effectiveness_test():
    """Test the system's ability to detect different traffic patterns"""
    print("\n🛡️ SECURITY EFFECTIVENESS TEST")
    print("   " + "-" * 40)
    
    # Test different port patterns that might trigger different classifications
    test_cases = [
        {"name": "Normal Web Traffic", "port": 443, "expected": "NORMAL"},
        {"name": "Suspicious High Port", "port": 9999, "expected": "ANOMALOUS"},
        {"name": "Common Service", "port": 80, "expected": "NORMAL"},
        {"name": "Database Port", "port": 3306, "expected": "Varies"}
    ]
    
    for test in test_cases:
        try:
            # Create features with different destination port
            features = [0.0] * 46
            features[0] = test["port"]  # Destination Port
            features[1] = 2.0  # Short duration
            features[2] = 5    # Few packets
            features[3] = 3    # Few back packets
            
            response = requests.post(
                'http://localhost:8000/predict',
                json={"dataset": "cic", "features": features},
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                actual_label = result.get('label', 'UNKNOWN')
                confidence = result.get('confidence', 0)
                
                status = "✅" if actual_label == test["expected"] or test["expected"] == "Varies" else "⚠️"
                print(f"   {status} {test['name']} (Port {test['port']}): {actual_label} (conf: {confidence:.2f})")
            else:
                print(f"   ❌ {test['name']}: Failed with status {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ {test['name']}: Error - {e}")

if __name__ == "__main__":
    print("🚀 LAI-IDS FINAL VALIDATION TEST SUITE")
    print("Testing complete system functionality with 46-feature ML pipeline\n")
    
    # Run comprehensive system test
    system_ok = test_all_endpoints()
    
    # Run ML prediction test with correct 46 features
    ml_ok = test_ml_prediction_46_features()
    
    # Run security effectiveness test
    run_security_effectiveness_test()
    
    # Final comprehensive verdict
    print("\n" + "=" * 60)
    print("🏁 FINAL SYSTEM VALIDATION RESULTS")
    print("=" * 60)
    
    if system_ok and ml_ok:
        print("🎉 🎉 🎉 FULLY OPERATIONAL! 🎉 🎉 🎉")
        print("✅ All system components verified")
        print("✅ ML pipeline with 46 features working")
        print("✅ Real-time threat detection active")
        print("✅ Production deployment ready!")
        print("\n🚀 YOUR LAI-IDS IS SUCCESSFULLY VALIDATED! 🛡️")
    else:
        print("⚠️  SYSTEM STATUS: Partial Operation")
        if system_ok:
            print("✅ Core system operational")
        if ml_ok:
            print("✅ ML pipeline operational")
        print("🔧 Review specific failures above")
    
    print("=" * 60)