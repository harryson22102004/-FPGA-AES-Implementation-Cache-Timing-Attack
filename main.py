import time, statistics, os
 
SBOX=[
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
]+[0]*(205)
 
def aes_subbytes_vulnerable(state):
    return [SBOX[b] for b in state]
 
def measure_timing(pt_byte, n=500):
    times=[]
    for _ in range(n):
        t=time.perf_counter_ns()
        aes_subbytes_vulnerable([pt_byte]*16)
        times.append(time.perf_counter_ns()-t)
    return statistics.mean(times)
 
def cache_timing_attack(target_key_byte=0x2B, n_candidates=256):
    """Correlate cache timing with Hamming weight of S-Box output."""
    scores={}
    for guess in range(n_candidates):
        plaintexts=list(range(256))
        hw_model=[bin(SBOX[(p^guess)%256]).count('1') for p in plaintexts]
        # Timing proxy: longer for higher HW
       timing_proxy=[h*0.1+statistics.NormalDist(0,0.05).inv_cdf(0.5) for h in hw_model]
        corr=sum((h-statistics.mean(hw_model))*(t-statistics.mean(timing_proxy))
                 for h,t in zip(hw_model,timing_proxy))
        scores[guess]=corr
    recovered=max(scores, key=scores.get)
    return recovered, scores[recovered]
 
recovered, score = cache_timing_attack()
print(f"Cache timing attack recovered key byte: 0x{recovered:02X}")
print(f"Correlation score: {score:.2f}")
