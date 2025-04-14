package util;

import java.util.Date;

public class WorkSheet {

    public String reference;
    public String description;
    public String workType;
    public String adjudicationState;

    //After being accepted

    public String adjudicationDate;
    public String workStartDate;
    public String workEndDate;
    public String employerNIF;
    public String workState;
    public String observations;




    public WorkSheet() {

    }

    public WorkSheet(String reference, String description, String workType, String adjudicationState){
        this.reference = reference;
        this.description = description;
        this.workType = workType;
        this.adjudicationState = adjudicationState;
    }


    private boolean nonEmptyOrBlankField(String field) {
        return field != null && !field.isBlank();
    }

    private boolean nonEmptyOrBlankField(Date field) {
        return field != null ;
    }



    public boolean validRegistration() {
        return nonEmptyOrBlankField(reference) &&
                nonEmptyOrBlankField(description) &&
                nonEmptyOrBlankField(workType) &&
                nonEmptyOrBlankField(adjudicationState) &&
                (adjudicationState.equals("ADJUDICADO") || adjudicationState.equals("NÃO ADJUDICADO")) &&
                (workType.equals("Propriedade Pública") || workType.equals("Propriedade Privada"));

    }



    public boolean validAdjudication() {
        return nonEmptyOrBlankField(reference) &&
                nonEmptyOrBlankField(adjudicationDate) &&
                nonEmptyOrBlankField(workStartDate) &&
                nonEmptyOrBlankField(workEndDate) &&
                nonEmptyOrBlankField(employerNIF) &&
                nonEmptyOrBlankField(workState) &&
                nonEmptyOrBlankField(observations)&&
                validWorkState();
    }
    public boolean invalidRegistration() {
            return !nonEmptyOrBlankField(adjudicationDate) &&
                    !nonEmptyOrBlankField(workStartDate) &&
                    !nonEmptyOrBlankField(workEndDate) &&
                    !nonEmptyOrBlankField(employerNIF) &&
                    !nonEmptyOrBlankField(workState) &&
                    !nonEmptyOrBlankField(observations);
    }

    public boolean hasOnlyAdjudicationData() {
        return !nonEmptyOrBlankField(description) &&
                !nonEmptyOrBlankField(workType) &&
                !nonEmptyOrBlankField(adjudicationState) &&
                validAdjudication(); // Inclui a validação dos campos obrigatórios
    }

    public boolean validWorkState() {
        return (workState.equals("NÃO INICIADO") || workState.equals("EM CURSO") || workState.equals("CONCLUÍDO"));

    }




}
