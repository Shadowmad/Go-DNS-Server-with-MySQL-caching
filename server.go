package main

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
	"strings"
	"time"
	"fmt"
	"github.com/elgs/gosqljson"
	"strconv"
)


func main() {
	server := &dns.Server{Addr: ":10015", Net: "udp", Handler: nil, Unsafe: true}
	dns.HandleFunc(".", handlerToAnswer)
	err := server.ListenAndServe()
	if(err !=nil){
		fmt.Println(err);
	}
}

/*Function that strips undesired characters from string */
func stripchars(str, chr string) string {
	return strings.Map(func(r rune) rune {
		if strings.IndexRune(chr, r) < 0 {
			return r
		}
		return -1
	}, str)
}

/* Function that caches new information to DB */
func dbWriter(gotAns []dns.RR, db *sql.DB, question string) {
	stmIns, err := db.Prepare("INSERT INTO dnsCache(`question`,`name`,`typeC`,`classC`,`dateCame`,`TTL`,`dateExpire`,`ip`) VALUES (?,?,?,?,?,?,?,?)")
	if err != nil {
		panic(err.Error())
	}
	for _, element := range gotAns {
		toDb := element.String()
		toDb = stripchars(toDb, ";")
		toDbSplit := strings.Split(toDb, "\t")
		
		timeLeft, _ := time.ParseDuration(toDbSplit[1]+"s");
		_, err = stmIns.Exec(question,toDbSplit[0], toDbSplit[3], toDbSplit[2], time.Now().UTC(),toDbSplit[1], time.Now().UTC().Add(timeLeft),toDbSplit[4])
	}
	
}

/* Delete dead TTL */ 
func deleteTable(db *sql.DB, id []string){
	stm,err := db.Prepare("DELETE FROM dnsCache WHERE `id`=?");
	if(err !=nil){
		panic(err.Error());
	}
	defer stm.Close();
	for _, element := range id{
		_, err = stm.Exec(element);
		if err !=nil{
			panic(err.Error());
		}
	}
}

/* Function that gets needed tables */
func dbRespond(db *sql.DB, question string)(answerToHand []dns.RR){
	var deleter []string
	var handOver []string
	const layout =  "2006-01-02 15:04:05"
	stm :="SELECT * FROM dnsCache WHERE question=?";
	data, _ := gosqljson.QueryDbToMap(db, "none" , stm, question)
	if(len(data) >0){
		for i := 0; i<len(data); i++{
			timer,_ :=time.Parse(layout, data[i]["dateExpire"])
			if(time.Now().UTC().After(timer)){
				deleter = append(deleter, data[i]["id"]);
			}else{
				temp := data[i]["name"]+" "+stripchars(strconv.Itoa(int(time.Now().UTC().Sub(timer).Seconds())),"-")+" "+data[i]["classC"]+" "+data[i]["typeC"]+" "+data[i]["ip"]
				handOver = append(handOver, temp);
			}
		}
		go deleteTable(db, deleter);
		answerToHand = buildRR(handOver);
	}else if(len(data) == 0){
		answerToHand = nil
	}
	return
}

/* Function that creates RR records in array from DB (accessible only from dbRespond function) */
func buildRR(handOver []string)(answerHand []dns.RR){
	for _, stringAns := range handOver{
		temp, err:= dns.NewRR(stringAns)
		if(err !=nil){
			panic(err.Error());
		}
		answerHand = append(answerHand, temp);
	}
	return
}

func handlerToAnswer(w dns.ResponseWriter, r *dns.Msg) {
	db, err := sql.Open("mysql", "inserter:qwerty@/dnsServerCache") //Handler for database
	if err != nil {
		panic(err.Error()) // Just for example purpose. You should use proper error handling instead of panic
	}
	
	
	answer := new(dns.Msg) //Set answer to client
	answer.SetReply(r)     //Set reply flag and start collecting data for reply
	var answersAll []dns.RR  
	answersAll = dbRespond(db,r.Question[0].String())
	if(len(answersAll) != 0){
		for _, answers := range answersAll {
			answer.Answer = append(answer.Answer, answers);
		}
	}else{	
		client := new(dns.Client)
		var err1 error 
		config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		answer, _, err1 = client.Exchange(r, config.Servers[0]+":"+config.Port)
		if err1 != nil {
			panic(err1.Error());
		}
		if r.Rcode != dns.RcodeSuccess {
			return
		}
		go dbWriter(answer.Answer,db,r.Question[0].String())		
	}
	w.WriteMsg(answer)
}
