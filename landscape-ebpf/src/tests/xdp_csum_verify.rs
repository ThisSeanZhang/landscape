#[cfg(test)]
mod xdp_csum_verify_tests {
    use std::mem::MaybeUninit;

    use libbpf_rs::{
        skel::{OpenSkel, SkelBuilder as _},
        MapCore, MapFlags, ProgramInput,
    };

    use crate::tests::test_csum_verify_skel::TestCsumVerifySkelBuilder;

    fn r(map: &libbpf_rs::Map, key: u32) -> u64 {
        let k = key.to_ne_bytes();
        let v = map.lookup(&k, MapFlags::ANY).unwrap().unwrap();
        u64::from_ne_bytes(v[..8].try_into().unwrap())
    }

    #[test]
    fn verify_bpf_csum_diff_ip() {
        let skel_builder = TestCsumVerifySkelBuilder::default();
        let mut open_obj = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_obj).unwrap();
        let skel = open_skel.load().unwrap();

        let prog = skel.progs.test_csum_ip;
        let mut dummy = vec![0u8; 64];
        let input = ProgramInput { data_in: Some(&mut dummy), ..Default::default() };
        let _ = prog.test_run(input).expect("test_run failed");

        let map = &skel.maps.csum_map;

        let r0 = r(map, 0);
        let r1 = r(map, 1);
        let r2 = r(map, 2);
        let r3 = r(map, 3);
        let r4 = r(map, 4);
        let r5 = r(map, 5);
        let r6 = r(map, 6);
        let r7 = r(map, 7);

        let r8 = r(map, 8);
        let r9 = r(map, 9);
        let r10 = r(map, 10);
        let r11 = r(map, 11);

        let msg = format!(
            "\n=== BPF csum_diff LE/BE comparison ===\n\
             A: bpf_htonl(.)   B: hardcoded LE\n\
             [key 0] IP direct (A) = 0x{r0:04x}\n\
             [key 1] IP direct (B) = 0x{r1:04x}\n\
             [key 2] raw delta (A)  = 0x{r2:08x}\n\
             [key 3] raw delta (B)  = 0x{r3:08x}\n\
             [key 4] *(u32*)&old_a   = 0x{r4:08x}\n\
             [key 5] *(u32*)&old_b   = 0x{r5:08x}\n\
             [key 6] csum_fold ch (A)= 0x{r6:04x}  (correct=0xbb90)\n\
             [key 7] csum_fold ch (B)= 0x{r7:04x}\n\
             [key 8] *(u32*)&new_a   = 0x{r8:08x}\n\
             [key 9] *(u32*)&new_b   = 0x{r9:08x}\n\
             [key 10] *(u16*)&csum_a = 0x{r10:04x}\n\
             [key 11] *(u16*)&csum_b = 0x{r11:04x}\n",
        );

        /* A and B must have same memory bytes, so results should match */
        assert_eq!(r4, r5, "old_addr memory differs; {msg}");
        assert_eq!(r8, r9, "new_addr memory differs; {msg}");
        assert_eq!(r10, r11, "csum memory differs; {msg}");

        eprintln!("{msg}");
    }
}
