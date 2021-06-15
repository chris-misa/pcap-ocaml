(*
 * Main entry point and implementation for simple header-dump operation
 *)
open Pcap
open Printf

open Utils
open Builtins

(* See builtins.ml for definitions of building blocks used here *)
(* '@=>' is just a right-associative application to avoid nasty nested parens *)

let ident k = 
    (map (fun p -> Tuple.filter (fun k _ -> not (String.equal k "eth.src" || String.equal k "eth.dst")) p))
    @=> k

(* Sonata 1 *)
let tcp_new_cons k =
    let threshold = 40 in
    (epoch 1.0 "eid")
    @=> (filter (fun p ->
                    (find_int "ipv4.proto" p) = 6 &&
                    (find_int "l4.flags" p) = 2))
    @=> (groupby (get_keys ["ipv4.dst"]) count "cons")
    @=> (filter (key_geq_int "cons" threshold))
    @=> k

(* Sonata 2 *)
let ssh_brute_force k =
    let threshold = 40 in
    (epoch 1.0 "eid") (* might need to elongate epoch for this one... *)
    @=> (filter (fun p ->
                    (find_int "ipv4.proto" p) = 6 &&
                    (find_int "l4.dport" p) = 22))
    @=> (distinct (get_keys ["ipv4.src" ; "ipv4.dst" ; "ipv4.len"]))
    @=> (groupby (get_keys ["ipv4.dst" ; "ipv4.len"]) count "srcs")
    @=> (filter (key_geq_int "srcs" threshold))
    @=> k

(* Sonata 3 *)
let super_spreader k =
    let threshold = 40 in
    (epoch 1.0 "eid")
    @=> (distinct (get_keys ["ipv4.src" ; "ipv4.dst"]))
    @=> (groupby (get_keys ["ipv4.src"]) count "dsts")
    @=> (filter (key_geq_int "dsts" threshold))
    @=> k

(* Sonata 4 *)
let port_scan k =
    let threshold = 40 in
    (epoch 1.0 "eid")
    @=> (distinct (get_keys ["ipv4.src" ; "l4.dport"]))
    @=> (groupby (get_keys ["ipv4.src"]) count "ports")
    @=> (filter (key_geq_int "ports" threshold))
    @=> k

(* Sonata 5 *)
let ddos k =
    let threshold = 45 in
    (epoch 1.0 "eid")
    @=> (distinct (get_keys ["ipv4.src" ; "ipv4.dst"]))
    @=> (groupby (get_keys ["ipv4.dst"]) count "srcs")
    @=> (filter (key_geq_int "srcs" threshold))
    @=> k

(* Sonata 6 --- Note this implements the Sonata semantic of this query *NOT* the intended semantic from NetQRE *)
let syn_flood_sonata k =
    let threshold = 3 in
    let epoch_dur = 1.0 in
    let syns k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        (find_int "l4.flags" p) = 2))
        @=> (groupby (get_keys ["ipv4.dst"]) count "syns")
        @=> k'
    in let synacks k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        (find_int "l4.flags" p) = 18))  (* --- corrected *)
        @=> (groupby (get_keys ["ipv4.src"]) count "synacks")
        @=> k'
    in let acks k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        (find_int "l4.flags" p) = 16))
        @=> (groupby (get_keys ["ipv4.dst"]) count "acks")
        @=> k'
    in let j1, o3 =
        (join
            (fun p -> ((get_keys ["host"] p), (get_keys ["syns+synacks"] p)))
            (fun p -> ((get_keys_rename [("ipv4.dst","host")] p), (get_keys ["acks"] p))))
        @==> (map (fun p -> Tuple.add "syns+synacks-acks" (Int ((find_int "syns+synacks" p) - (find_int "acks" p))) p))
        @=> (filter (key_geq_int "syns+synacks-acks" threshold))
        @=> k
    in let o1, o2 = 
        (join
            (fun p -> ((get_keys_rename [("ipv4.dst","host")] p), (get_keys ["syns"] p)))
            (fun p -> ((get_keys_rename [("ipv4.src","host")] p), (get_keys ["synacks"] p))))
        @==> (map (fun p -> Tuple.add "syns+synacks" (Int ((find_int "syns" p) + (find_int "synacks" p))) p))
        @=> j1
    in [syns @=> o1 ; synacks @=> o2 ; acks @=> o3]
    

(* Sonata 7 *)
let completed_flows k =
    let threshold = 1 in
    let epoch_dur = 30.0 in (* Adjusted... *)
    let syns k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        (find_int "l4.flags" p) = 2))
        @=> (groupby (get_keys ["ipv4.dst"]) count "syns")
        @=> k'
    in let fins k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        ((find_int "l4.flags" p) land 1) = 1))
        @=> (groupby (get_keys ["ipv4.src"]) count "fins")
        @=> k'
    in let o1, o2 =
        (join
            (fun p -> ((get_keys_rename [("ipv4.dst","host")] p), (get_keys ["syns"] p)))
            (fun p -> ((get_keys_rename [("ipv4.src","host")] p), (get_keys ["fins"] p))))
        @==> (map (fun p -> Tuple.add "diff" (Int ((find_int "syns" p) - (find_int "fins" p))) p))
        @=> (filter (key_geq_int "diff" threshold))
        @=> k
    in [syns @=> o1 ; fins @=> o2]

(* Sonata 8 *)
let slowloris k =
    let t1 = 5 in
    let t2 = 500 in
    let t3 = 90 in
    let epoch_dur = 1.0 in
    let n_conns k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p -> (find_int "ipv4.proto" p) = 6))
        @=> (distinct (get_keys ["ipv4.src" ; "ipv4.dst" ; "l4.sport"]))
        @=> (groupby (get_keys ["ipv4.dst"]) count "n_conns")
        @=> (filter (fun p -> (find_int "n_conns" p) >= t1))
        @=> k'
    in let n_bytes k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p -> (find_int "ipv4.proto" p) = 6))
        @=> (groupby (get_keys ["ipv4.dst"]) (sum "ipv4.len") "n_bytes")
        @=> (filter (fun p -> (find_int "n_bytes" p) >= t2))
        @=> k'
    in let o1, o2 =
        (join
            (fun p -> (get_keys ["ipv4.dst"] p, get_keys ["n_conns"] p))
            (fun p -> (get_keys ["ipv4.dst"] p, get_keys ["n_bytes"] p)))
        @==> (map (fun p -> Tuple.add "bytes_per_conn" (Int ((find_int "n_bytes" p) / (find_int "n_conns" p))) p))
        @=> (filter (fun p -> (find_int "bytes_per_conn" p) <= t3))
        @=> k
    in [n_conns @=> o1 ; n_bytes @=> o2]

let join_test k =
    let epoch_dur = 1.0 in
    let syns k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        (find_int "l4.flags" p) = 2))
        @=> k'
    in let synacks k' =
        (epoch epoch_dur "eid")
        @=> (filter (fun p ->
                        (find_int "ipv4.proto" p) = 6 &&
                        (find_int "l4.flags" p) = 18))
        @=> k'
    in let o1, o2 =
        (join
            (fun p -> ((get_keys_rename [("ipv4.src","host")] p), (get_keys_rename [("ipv4.dst","remote")] p)))
            (fun p -> ((get_keys_rename [("ipv4.dst","host")] p), (get_keys ["time"] p))))
        @==> k
    in [syns @=> o1 ; synacks @=> o2]

let current_queries = [ident (dump_csv stdout)]

let process_file file_name queries =
    let h, buf = read_header file_name in
    let module H = (val h: Pcap.HDR) in
    let header, body = Cstruct.split buf sizeof_pcap_header in
    let network = Int32.to_int (H.get_pcap_header_network header) in
    Cstruct.fold (fun _ (hdr, pkt) ->
        match (parse_pkt network h hdr pkt) with
        | Some p -> List.iter (fun q -> q.next p) queries
        | None -> ()
    ) (Pcap.packets h body) ()

(*
 * Main entrypoint
 *)
let () =
    if Array.length Sys.argv = 2
    then process_file Sys.argv.(1) current_queries
    else printf "Expected <pcap file path> as argument.\n"
