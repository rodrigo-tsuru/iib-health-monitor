package br.com.tsuru.iib.health;

public class Issue {

	public enum SEVERITY {WARNING,MINOR,MAJOR};
	
	private SEVERITY severity;
	private String description;
	private String reference;
	private String solution;
	public Issue(SEVERITY severity, String description, String reference,
			String solution) {
		this.severity = severity;
		this.description = description;
		this.reference = reference;
		this.solution = solution;
	}	
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getReference() {
		return reference;
	}
	public void setReference(String reference) {
		this.reference = reference;
	}

	public String getSolution() {
		return solution;
	}
	public void setSolution(String solution) {
		this.solution = solution;
	}
	public SEVERITY getSeverity() {
		return severity;
	}
	public void setSeverity(SEVERITY severity) {
		this.severity = severity;
	}
}
